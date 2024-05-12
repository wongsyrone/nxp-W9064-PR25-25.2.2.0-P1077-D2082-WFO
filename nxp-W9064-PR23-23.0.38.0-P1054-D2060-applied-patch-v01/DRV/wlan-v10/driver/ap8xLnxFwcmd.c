/** @file ap8xLnxFwcmd.c
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

/** include files **/
#include "ap8xLnxRegs.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxVer.h"
#include "bcngen.h"
#include "wds.h"
#include "keyMgmt_if.h"
#ifdef NEW_DP
#include "ap8xLnxAcnt.h"
#endif
#if defined(AIRTIME_FAIRNESS)
#include "ap8xLnxAtf.h"
#endif /* AIRTIME_FAIRNESS */
#include <asm/siginfo.h>	//siginfo
#include <linux/rcupdate.h>	//rcu_read_lock
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,10,0)
#include <linux/sched/signal.h>	//find_task_by_pid_type
#else
#include <linux/sched.h>	//find_task_by_pid_type
#endif

#include <linux/debugfs.h>
#include <linux/uaccess.h>
#if defined (MRVL_WAPI) || defined (WTP_SUPPORT)
#include "ap8xLnxIoctl.h"
#endif
#include "macMgmtMlme.h"

#include <linux/sched.h>
#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#include "mlmeApi.h"
#include "wlApi.h"

/** local definitions **/
#define MAX_WAIT_FW_COMPLETE_ITERATIONS    2000000	//usec. Change from 10sec to 2 sec usec
#define WEP_KEY_40_BIT_LEN                 0x0005	// 40 bit
#define WEP_KEY_104_BIT_LEN                0x000D	// 104 bit

#define MAX_NUM_STA_ENCR_KEY_ENTRIES 128

#define MWL_SPIN_LOCK(X) SPIN_LOCK_IRQSAVE(X, flags)
#define MWL_SPIN_UNLOCK(X)      SPIN_UNLOCK_IRQRESTORE(X, flags)

/* default settings */

/** external functions **/
extern void SendBFMRconfig(struct net_device *dev);
extern void ListPutItemFILO(List * me, ListItem * Item);
extern void wlInterruptUnMask(struct net_device *netdev, int mask);
extern void wlInterruptMask(struct net_device *netdev, int mask);
extern int WlLoadRateGrp(struct net_device *netdev);
extern void keymgmt_aesInfoGet(UINT8 ouiType, UINT32 * pKeyTypeId,
			       UINT32 * pKenLen);
#ifdef SOC_W906X
extern void wlmon_log_buffer(struct net_device *netdev, UINT8 * buf,
			     UINT32 len);
extern void wlmon_log_pfw_schInfo(struct net_device *netdev,
				  QS_TX_SCHEDULER_INFO_t * pbuf);
extern void update_nontxd_bssid_profile_ssid(vmacApInfo_t * vmacSta_p,
					     void *pssidIE);
extern void update_nontxd_bssid_profile_cap(vmacApInfo_t * vmacSta_p,
					    UINT16 CapInfo);
extern void update_nontxd_bssid_profile_bssidIdx(vmacApInfo_t * vmacSta_p);
#endif

/** external data **/
extern UINT8 dfs_test_mode;
#ifdef  BARBADOS_DFS_TEST
extern UINT8 dfs_probability;
#endif
/** internal functions **/
#ifdef MRVL_DFS
int DecideDFSOperation(struct net_device *netdev, BOOLEAN bChannelChanged,
		       BOOLEAN bBandWidthChanged, UINT8 currDFSState,
		       UINT8 newDFSState, MIB_802DOT11 * mib);
#endif
static int wlexecuteCommand(struct net_device *, unsigned short);
static void wlsendCommand(struct net_device *);
static UINT8 *getCmdRspErrorStr(UINT16 reason) __attribute__ ((unused));

static int wlwaitForComplete(struct net_device *, u_int16_t);
#ifdef WL_DEBUG
static char *wlgetCmdString(u_int16_t cmd);
static char *wlgetCmdResultString(u_int16_t result);
#endif
static char *wlgetDrvName(struct net_device *netdev) __attribute__ ((unused));
#ifndef SOC_W906X
static int wlFwSetMaxTxPwr(struct net_device *netdev);
static int wlFwSetCSAdaptMode(struct net_device *netdev);
static int wlFwSetOptimizationLevel(struct net_device *netdev, UINT8 mode);
static int wlFwGetPwrCalTable(struct net_device *netdev);
#endif
static int wlFwSetAdaptMode(struct net_device *netdev);
static int wlFwSetNProt(struct net_device *netdev, UINT32 mode);
static int wlFwGetRegionCode(struct net_device *netdev);
static int wlFwSetRifs(struct net_device *netdev, UINT8 QNum);
static int wlFwSetHTStbc(struct net_device *netdev, UINT32 mode);
extern int wlFwSetCDD(struct net_device *netdev, UINT32 cdd_mode);
static int wlFwSetBFType(struct net_device *netdev, UINT32 mode);
#ifdef QUEUE_STATS
int wlCheckBa(struct net_device *netdev, UINT8 * addr);
#endif
int wlFwSetBWSignalType(struct net_device *netdev, UINT32 mode, UINT8 val);

/** public data **/

/** private data **/

//static u_int32_t numStaEncrKeyEntries = 0;
/** public functions **/

int wlRegBB(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val);
int wlFwSetNProtOpMode(struct net_device *netdev, UINT8 mode);

#ifdef SOC_W906X
static void
SMAC_RX_ENABLE(struct wlprivate *wlpptr, MIB_802DOT11 * mib, UINT32 macId)
{
	if (macId != 0xffffffff)
		*(mib->mib_rx_enable) |= (1 << macId);
	wl_util_lock(wlpptr->netDev);
	*(u32*)(&((SMAC_CTRL_BLK_st*)wlpptr->ioBase0)->config.rxEnable) = 1;
	wl_util_unlock(wlpptr->netDev);
}

static void
SMAC_RX_DISABLE(struct wlprivate *wlpptr, MIB_802DOT11 * mib, UINT32 macId)
{
	//check 32 BSS and Promicous  
	if (macId != 0xffffffff)
		*(mib->mib_rx_enable) &= ~(1 << macId);

	wl_util_lock(wlpptr->netDev);
	if (mib && (*(mib->mib_rx_enable) == 0) &&
	    (*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.opMode)
	     == 0)) {
		*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.
			  rxEnable) = 0;
	}

	wl_util_unlock(wlpptr->netDev);
}
#endif /* #ifdef SOC_W906X */

INLINE u_int8_t
GET_CMD_SEQ_NUM(struct wlprivate *wlpptr)
{
#ifdef SOC_W906X
	u_int8_t retNum;

	if (wlpptr->master) {
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);
	}
	retNum = wlpptr->cmd_seqno & 0x7F;
	wlpptr->cmd_seqno += 1;
	return retNum;
#else
	return 0;
#endif
}

UINT8
keymgmt_aesModeGet(UINT8 ouiType)
{
	if (ouiType == IEEEtypes_RSN_CIPHER_SUITE_CCMP)
		return EncrTypeAes;
	else if (ouiType == IEEEtypes_RSN_CIPHER_SUITE_GCMP)
		return EncrTypeGcmp128;
	else if (ouiType == IEEEtypes_RSN_CIPHER_SUITE_GCMP_256)
		return EncrTypeGcmp256;
	else if (ouiType == IEEEtypes_RSN_CIPHER_SUITE_CCMP_256)
		return EncrTypeCcmp256;
	else
		return EncrTypeDisable;	//Not support
}

void
wlFwCmdComplete(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef WL_DEBUG
	u_int16_t cmd =
		ENDIAN_SWAP16(((FWCmdHdr *) wlpptr->pCmdBuf)->Cmd) & 0x7fff;
#endif
	u_int16_t result =
		ENDIAN_SWAP16(((FWCmdHdr *) wlpptr->pCmdBuf)->Result);

	if (result != HostCmd_RESULT_OK) {
		WLDBG_INFO(DBG_LEVEL_0,
			   "%s: FW cmd 0x%04x=%s failed: 0x%04x=%s\n",
			   wlgetDrvName(netdev), cmd, wlgetCmdString(cmd),
			   result, wlgetCmdResultString(result));
	}
}

int
wlFwGetHwSpecs(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_GET_HW_SPEC *pCmd =
		(HostCmd_DS_GET_HW_SPEC *) & wlpptr->pCmdBuf[0];
	unsigned long flags;
	int retrycnt = 2;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

	printk("wlFwGetHwSpecs pCmd = %p \n", pCmd);

	memset(pCmd, 0x00, sizeof(HostCmd_DS_GET_HW_SPEC));
	memset(&pCmd->PermanentAddr[0], 0xff, ETH_ALEN);
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_HW_SPEC);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_GET_HW_SPEC));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->ulFwAwakeCookie =
		ENDIAN_SWAP32((unsigned int)wlpptr->wlpd_p->pPhysCmdBuf + 2048);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_GET_HW_SPEC));

	while (wlexecuteCommand(netdev, HostCmd_CMD_GET_HW_SPEC)) {
		printk("failed execution");
		mdelay(1000);
		printk(" Repeat wlFwGetHwSpecs = %p \n", pCmd);
		if (retrycnt-- <= 0) {
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
	}

	memcpy(&wlpptr->hwData.macAddr[0], pCmd->PermanentAddr, ETH_ALEN);
#ifndef SOC_W906X
#ifndef NEW_DP
	wlpptr->wlpd_p->descData[0].wcbBase =
		ENDIAN_SWAP32(pCmd->WcbBase0) & 0x0000ffff;
#if NUM_OF_DESCRIPTOR_DATA >3
	for (i = 1; i < TOTAL_TX_QUEUES; i++)
		wlpptr->wlpd_p->descData[i].wcbBase =
			ENDIAN_SWAP32(pCmd->WcbBase[i - 1]) & 0x0000ffff;
#endif

#else
	wlpptr->wlpd_p->TxDescLimit = ENDIAN_SWAP32(pCmd->TxDescLimit);
#endif
	wlpptr->wlpd_p->descData[0].rxDescRead =
		ENDIAN_SWAP32(pCmd->RxPdRdPtr) & 0x0000ffff;
	wlpptr->wlpd_p->descData[0].rxDescWrite =
		ENDIAN_SWAP32(pCmd->RxPdWrPtr) & 0x0000ffff;
#endif /* #ifndef SOC_W906X */
	wlpptr->hwData.regionCode = ENDIAN_SWAP16(pCmd->RegionCode) & 0x00ff;
	//      domainSetDomain(wlpptr->wlpd_p->hwData.regionCode);
	wlpptr->hwData.fwReleaseNumber = ENDIAN_SWAP32(pCmd->FWReleaseNumber);
	wlpptr->hwData.maxNumTXdesc = ENDIAN_SWAP16(pCmd->NumOfWCB);
	wlpptr->hwData.maxNumMCaddr = ENDIAN_SWAP16(pCmd->NumOfMCastAddr);
	wlpptr->hwData.numAntennas = ENDIAN_SWAP16(pCmd->NumberOfAntenna);
	wlpptr->hwData.hwVersion = pCmd->Version;
	wlpptr->hwData.hostInterface = pCmd->HostIf;
#ifdef SOC_W906X
	wlpptr->hwData.sfwReleaseNumber = ENDIAN_SWAP32(pCmd->SFWReleaseNumber);
	wlpptr->hwData.ulShalVersion = ENDIAN_SWAP16(pCmd->ulShalVersion);
	mdelay(10);		//tmp solution for command response status updated before content
	wlpptr->hwData.smacReleaseNumber = ENDIAN_SWAP32(pCmd->ulSmacVersion);
	printk("mac version %x\n", wlpptr->hwData.smacReleaseNumber);
#endif
	WLDBG_EXIT_INFO(DBG_LEVEL_0,
			"region code is %i (0x%x), HW version is %i (0x%x)",
			wlpptr->hwData.regionCode, wlpptr->hwData.regionCode,
			wlpptr->hwData.hwVersion, wlpptr->hwData.hwVersion);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return SUCCESS;
}

int
wlFwSetHwSpecs(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_SET_HW_SPEC *pCmd =
		(HostCmd_DS_SET_HW_SPEC *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	UINT32 m, chunksize = 0, log2 = 0;
#endif
#ifndef NEW_DP
	int i;
#endif
	WLDBG_ENTER(DBG_LEVEL_1);

#ifdef NEW_DP
#ifndef SOC_W906X
	/* Info for SOC team's debugging */
	printk("wlFwSetHwSpecs ...\n");
	printk("  -->pPhysTxRing     = %pad\n",
	       &wlpptr->wlpd_p->descData[0].pPhysTxRing);
	printk("  -->pPhysTxDoneRing = %pad\n",
	       &wlpptr->wlpd_p->descData[0].pPhysTxRingDone);
	printk("  -->pPhysRxRing     = %pad\n",
	       &wlpptr->wlpd_p->descData[0].pPhysRxRing);
	printk("  -->pPhysRxDoneRing = %pad\n",
	       &wlpptr->wlpd_p->descData[0].pPhysRxRingDone);

#ifndef NEWDP_ACNT_CHUNKS
//    printk("  -->pPhysAcntRing   = %pad\n", &wlpptr->wlpd_p->descData[0].pPhysAcntRing);      //0316
#endif
#endif /* #ifndef SOC_W906X */
	printk("  -->num tx desc %d num rx desc %d\n", MAX_NUM_TX_DESC,
	       MAX_NUM_RX_DESC);
#else
	/* Info for SOC team's debugging */
	printk("wlFwSetHwSpecs ...\n");
	printk("  -->pPhysTxRing[0] = %x\n",
	       wlpptr->wlpd_p->descData[0].pPhysTxRing);
	printk("  -->pPhysTxRing[1] = %x\n",
	       wlpptr->wlpd_p->descData[1].pPhysTxRing);
	printk("  -->pPhysTxRing[2] = %x\n",
	       wlpptr->wlpd_p->descData[2].pPhysTxRing);
	printk("  -->pPhysTxRing[3] = %x\n",
	       wlpptr->wlpd_p->descData[3].pPhysTxRing);
	printk("  -->pPhysRxRing    = %x\n",
	       wlpptr->wlpd_p->descData[0].pPhysRxRing);
	printk("  -->numtxq %d wcbperq %d totalrxwcb %d \n",
	       NUM_OF_DESCRIPTOR_DATA, MAX_NUM_TX_DESC, MAX_NUM_RX_DESC);
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_SET_HW_SPEC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_HW_SPEC);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_SET_HW_SPEC));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
#ifdef SOC_W906X
	pCmd->hostPciIntrType = wlpptr->intr_type;
#endif

#ifdef NEW_DP
#ifndef SOC_W906X
	pCmd->WcbBase[0] =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysTxRing);
	pCmd->WcbBase[1] =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysTxRingDone);
	pCmd->WcbBase[2] =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysRxRing);
	pCmd->WcbBase[3] =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysRxRingDone);
#endif /* #ifndef SOC_W906X */

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	for (m = 0; m < ACNT_NCHUNK; m++) {
		pCmd->AcntBaseAddr[m] =
			ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].
				      pPhysAcntRing[m]);
	}

	chunksize = wlpptr->wlpd_p->AcntChunkInfo.SizeOfChunk;
	while (chunksize >>= 1)
		log2++;		//calculate log2 of chunk size

	pCmd->log2Chunk = ENDIAN_SWAP32(log2);

#else
	pCmd->AcntBaseAddr =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysAcntRing);
#endif

	pCmd->acntBufSize =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].AcntRingSize);

#else
	pCmd->WcbBase[0] = ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysTxRing);	//ENDIAN_SWAP32(wlpptr->descData[0].wcbBase)  & 0x0000ffff;

	for (i = 1; i < TOTAL_TX_QUEUES; i++)
		pCmd->WcbBase[i] = ENDIAN_SWAP32(wlpptr->wlpd_p->descData[i].pPhysTxRing);	//ENDIAN_SWAP32(      wlpptr->descData[1].wcbBase )   & 0x0000ffff;

	pCmd->TxWcbNumPerQueue = ENDIAN_SWAP32(MAX_NUM_TX_DESC);
	pCmd->NumTxQueues = ENDIAN_SWAP32(NUM_OF_DESCRIPTOR_DATA);
	pCmd->TotalRxWcb = ENDIAN_SWAP32(MAX_NUM_RX_DESC);
	pCmd->RxPdWrPtr =
		ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhysRxRing);

#endif
#if     defined(CLIENTONLY) || !defined(MBSS)
	pCmd->disablembss = 1;
#else
	pCmd->disablembss = 0;
#endif

#if NUMOFAPS == 1
	pCmd->disablembss = 1;
#endif

#ifdef SOC_W906X
	pCmd->eventq_addr = ENDIAN_SWAP32(wlpptr->event_bufq_paddr);
	pCmd->eventq_nums = ENDIAN_SWAP16(EVENT_BUFFQ_NUM);
	pCmd->eventq_size = ENDIAN_SWAP16(EVENT_BUFFQ_SIZE);
#endif

	if (wlexecuteCommand(netdev, HostCmd_CMD_SET_HW_SPEC)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_1, "failed execution");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return FAIL;
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return SUCCESS;
}

extern UINT32 dispRxPacket;
int
wlFwGetHwStats(struct net_device *netdev, char *page)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	char *p = page;
	int len = 0;
	HostCmd_DS_802_11_GET_STAT *pCmd =
		(HostCmd_DS_802_11_GET_STAT *) & wlpptr->pCmdBuf[0];

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_GET_STAT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	dispRxPacket = (dispRxPacket + 1) & 0x01;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_GET_STAT));
	if (wlexecuteCommand(netdev, HostCmd_CMD_802_11_GET_STAT)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return FAIL;
	}
	if (p) {
		p += sprintf(p, "TxRetrySuccesses.................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxRetrySuccesses));
		p += sprintf(p, "TxMultipleRetrySuccesses.........%10u\n",
			     ENDIAN_SWAP32((int)pCmd->
					   TxMultipleRetrySuccesses));
		p += sprintf(p, "TxFailures.......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxFailures));
		p += sprintf(p, "RTSSuccesses.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RTSSuccesses));
		p += sprintf(p, "RTSFailures......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RTSFailures));
		p += sprintf(p, "AckFailures......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->AckFailures));
		p += sprintf(p, "RxDuplicateFrames................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxDuplicateFrames));
		p += sprintf(p, "RxFCSErrors......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxFCSErrors));
		p += sprintf(p, "TxWatchDogTimeouts...............%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxWatchDogTimeouts));
		p += sprintf(p, "RxOverflows......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxOverflows));
		p += sprintf(p, "RxFragErrors.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxFragErrors));
		p += sprintf(p, "RxMemErrors......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxMemErrors));
		p += sprintf(p, "PointerErrors....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->PointerErrors));
		p += sprintf(p, "TxUnderflows.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxUnderflows));
		p += sprintf(p, "TxDone...........................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxDone));
		p += sprintf(p, "TxDoneBufTryPut..................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxDoneBufTryPut));
		p += sprintf(p, "TxDoneBufPut.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxDoneBufPut));
		p += sprintf(p, "Wait4TxBuf.......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->Wait4TxBuf));
		p += sprintf(p, "TxAttempts.......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxAttempts));
		p += sprintf(p, "TxSuccesses......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxSuccesses));
		p += sprintf(p, "TxFragments......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxFragments));
		p += sprintf(p, "TxMulticasts.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxMulticasts));
		p += sprintf(p, "RxNonCtlPkts.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxNonCtlPkts));
		p += sprintf(p, "RxMulticasts.....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxMulticasts));
		p += sprintf(p, "RxUndecryptableFrames............%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxUndecryptableFrames));
		p += sprintf(p, "RxICVErrors......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxICVErrors));
		p += sprintf(p, "RxExcludedFrames.................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxExcludedFrames));
		/* new from Aug'2012 */
		p += sprintf(p, "RxWeakIVCount....................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxWeakIVCount));
		p += sprintf(p, "RxUnicasts.......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxUnicasts));
		p += sprintf(p, "RxBytes..........................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxBytes));
		p += sprintf(p, "RxErrors.........................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxErrors));
		p += sprintf(p, "RxRTSCount.......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxRTSCount));
		p += sprintf(p, "TxCTSCount.......................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxCTSCount));
#ifdef MRVL_WAPI
		p += sprintf(p, "RxWAPIPNErrors...................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxWAPIPNErrors));
		p += sprintf(p, "RxWAPIMICErrors..................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxWAPIMICErrors));
		p += sprintf(p, "RxWAPINoKeyErrors................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->RxWAPINoKeyErrors));
		p += sprintf(p, "TxWAPINoKeyErrors................%10u\n",
			     ENDIAN_SWAP32((int)pCmd->TxWAPINoKeyErrors));
#endif
		len = (p - page);
	} else {
		printk("TxRetrySuccesses.................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxRetrySuccesses));
		printk("TxMultipleRetrySuccesses.........%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxMultipleRetrySuccesses));
		printk("TxFailures.......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxFailures));
		printk("RTSSuccesses.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RTSSuccesses));
		printk("RTSFailures......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RTSFailures));
		printk("AckFailures......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->AckFailures));
		printk("RxDuplicateFrames................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxDuplicateFrames));
		printk("RxFCSErrors......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxFCSErrors));
		printk("TxWatchDogTimeouts...............%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxWatchDogTimeouts));
		printk("RxOverflows......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxOverflows));
		printk("RxFragErrors.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxFragErrors));
		printk("RxMemErrors......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxMemErrors));
		printk("PointerErrors....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->PointerErrors));
		printk("TxUnderflows.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxUnderflows));
		printk("TxDone...........................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxDone));
		printk("TxDoneBufTryPut..................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxDoneBufTryPut));
		printk("TxDoneBufPut.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxDoneBufPut));
		printk("Wait4TxBuf.......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->Wait4TxBuf));
		printk("TxAttempts.......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxAttempts));
		printk("TxSuccesses......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxSuccesses));
		printk("TxFragments......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxFragments));
		printk("TxMulticasts.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxMulticasts));
		printk("RxNonCtlPkts.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxNonCtlPkts));
		printk("RxMulticasts.....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxMulticasts));
		printk("RxUndecryptableFrames............%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxUndecryptableFrames));
		printk("RxICVErrors......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxICVErrors));
		printk("RxExcludedFrames.................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxExcludedFrames));
		/* new from Aug'2012 */
		printk("RxWeakIVCount....................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxWeakIVCount));
		printk("RxUnicasts.......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxUnicasts));
		printk("RxBytes..........................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxBytes));
		printk("RxErrors.........................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxErrors));
		printk("RxRTSCount.......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxRTSCount));
		printk("TxCTSCount.......................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxCTSCount));
#ifdef MRVL_WAPI
		printk("RxWAPIPNErrors...................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxWAPIPNErrors));
		printk("RxWAPIMICErrors..................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxWAPIMICErrors));
		printk("RxWAPINoKeyErrors................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->RxWAPINoKeyErrors));
		printk("TxWAPINoKeyErrors................%10u\n",
		       ENDIAN_SWAP32((int)pCmd->TxWAPINoKeyErrors));
#endif
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return len;
}

static const char *
ntoa(const uint8_t * mac)
{
	static char addr[3 * 6 + 2];

	snprintf(addr, sizeof(addr), "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return addr;
}

int
wlFwGetAddrtable(struct net_device *netdev)
{
	const struct macaddr {
		unsigned char MacAddressInDB[10][6];	//data base entries
		unsigned char LegacyMacAddr[6];	//MAC will ACK this address
		unsigned char MBSSMacAddr[21][6];	//MAC will ACK these addresses
	} *p;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i = 0;
	HostCmd_DS_802_11_GET_STAT *pCmd =
		(HostCmd_DS_802_11_GET_STAT *) & wlpptr->pCmdBuf[0];

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(FWCmdHdr) + sizeof(const struct macaddr));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_GET_STAT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = 1;
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_GET_STAT));
	if (wlexecuteCommand(netdev, HostCmd_CMD_802_11_GET_STAT)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return FAIL;
	}
	p = (const struct macaddr *)&pCmd->TxRetrySuccesses;
	printk("LegacyMacAddr:\n");
	printk("  %s\n", ntoa(p->LegacyMacAddr));
	printk("MacAddressInDB:\n");
	for (i = 0; i < 8; i += 4) {
		printk("  %s", ntoa(p->MacAddressInDB[i + 0]));
		printk("  %s", ntoa(p->MacAddressInDB[i + 1]));
		printk("  %s", ntoa(p->MacAddressInDB[i + 2]));
		printk("  %s\n", ntoa(p->MacAddressInDB[i + 3]));
	}
	printk("  %s", ntoa(p->MacAddressInDB[i + 0]));
	printk("  %s\n", ntoa(p->MacAddressInDB[i + 1]));
	printk("MBSSMacAddr:\n");
	for (i = 0; i < 20; i += 4) {
		printk("  %s", ntoa(p->MBSSMacAddr[i + 0]));
		printk("  %s", ntoa(p->MBSSMacAddr[i + 1]));
		printk("  %s", ntoa(p->MBSSMacAddr[i + 2]));
		printk("  %s\n", ntoa(p->MBSSMacAddr[i + 3]));
	}
	printk("  %s\n", ntoa(p->MBSSMacAddr[i + 0]));
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return 0;
}

typedef struct FW_WepDefaultKeys_s {
	unsigned char WepDefaultKeyIdx;	// 1 to 4
	unsigned char WepDefaultKeyValue[13];	// 5 byte string
} FW_WEP_DEFAULT_KEYS;

typedef struct FWwepKeyMgmtInfo_t {
	/* XXX byte order dependent */
	unsigned short LoopBackOn:1;
	unsigned short WepEn:1;
	unsigned short IntrEn:1;
	unsigned short MultiCastEn:1;
	unsigned short BroadCastEn:1;
	unsigned short PromiscuousEn:1;
	unsigned short AllMultiCastEn:1;
	unsigned short KeyId:6;
	unsigned short HWSpecCmdDone:1;
	unsigned short WepType:1;
	unsigned short EnforceProtection:1;
	FW_WEP_DEFAULT_KEYS WepDefaultKeys[4];
} FWwepKeyMgmtInfo_t;

typedef struct {
	unsigned char UnicastKeyEnabled;
	unsigned char MulticastKeyEnabled;
	unsigned char UnicastKeyType;
	unsigned char MulticastKeyType;
	unsigned char RSNPairwiseTempKey[TK_SIZE_MAX];
	unsigned int RSNPwkTxMICKey[2];
	unsigned int RSNPwkRxMICKey[2];
	unsigned char RSNTempKey_group[TK_SIZE_MAX];
	unsigned int RSNTxMICKey_group[2];
	unsigned int RSNRxMICKey_group[2];
	unsigned int TxIV32;
	unsigned short TxIV16;
	unsigned int RxIV32;
	unsigned int groupTxIV32;
	unsigned short groupTxIV16;
	unsigned int groupRxIV32;
	unsigned char groupKeyIndex;
} FWkeyMgmtInfo_t;

int
wlFwGetEncrInfo(struct net_device *netdev, unsigned char *addr)
{
#ifdef SOC_W8964
	const struct encrdata {
		unsigned char StaEntryAddr[6];
		unsigned char EnHwEncr;	/*EncrTypeWep = 0, EncrTypeDisable = 1,
					   EncrTypeTkip = 4, EncrTypeAes = 6, EncrTypeMix = 7, */
		union {
			FWwepKeyMgmtInfo_t gWepKeyData;
			FWkeyMgmtInfo_t gKeyData;
		} PACK_END key;
	} PACK_END *p;
	static const char *encrnames[] =
		{ "WEP", "-", "#2", "#3", "TKIP", "#5", "AES", "MIX" };
	static const char *ciphernames[] =
		{ "WEP", "TKIP", "AES", "#3", "#4", "#5", "#6", "#7" };
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i = 0, j;
	HostCmd_DS_802_11_GET_STAT *pCmd =
		(HostCmd_DS_802_11_GET_STAT *) & wlpptr->pCmdBuf[0];
	U8 *bufpt = (U8 *) (&pCmd->TxRetrySuccesses);

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_GET_STAT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = 2;
	memcpy(bufpt, addr, 6);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_GET_STAT));
	if (wlexecuteCommand(netdev, HostCmd_CMD_802_11_GET_STAT)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return FAIL;
	}
	p = (const struct encrdata *)&pCmd->TxRetrySuccesses;
	printk("\n%s:\n", ntoa(p->StaEntryAddr));
	if (p->EnHwEncr == 1) {
		printk("Encryption disabled\n");
	} else if (p->EnHwEncr == 0) {
		printk("Mode    Loop    Wep     Intr	Mcast	Bcast	Promisc	AllMcast\n");
		printk("%4s	%s	%s	%s	%s	%s	%s	%s\n", encrnames[p->EnHwEncr & 7]
		       , p->key.gWepKeyData.LoopBackOn ? "ena" : "-",
		       p->key.gWepKeyData.WepEn ? "ena" : "-",
		       p->key.gWepKeyData.IntrEn ? "ena" : "-",
		       p->key.gWepKeyData.MultiCastEn ? "ena" : "-",
		       p->key.gWepKeyData.BroadCastEn ? "ena" : "-",
		       p->key.gWepKeyData.PromiscuousEn ? "ena" : "-",
		       p->key.gWepKeyData.AllMultiCastEn ? "ena" : "-");
		printk("KeyId   HWSpec  WepType	Protect\n");
		printk("%d	%s	%s	%s\n", p->key.gWepKeyData.KeyId,
		       p->key.gWepKeyData.
		       HWSpecCmdDone ? "yes" : "no",
		       p->key.gWepKeyData.WepType ? "104" : "40",
		       p->key.gWepKeyData.EnforceProtection ? "yes" : "no");
		for (i = 0; i < 4; i++) {
			printk("[%2d]",
			       p->key.gWepKeyData.WepDefaultKeys[i].
			       WepDefaultKeyIdx);
			for (j = 0; j < 13; j++)
				printk(" %02x",
				       p->key.gWepKeyData.WepDefaultKeys[i].
				       WepDefaultKeyValue[j]);
			printk("\n");
		}
	} else {
		printk("Mode    PTK     PTK type	GTK     GTK type	GTK Index\n");
		printk("%4s	%s	%s		%s	%s		%d\n", encrnames[p->EnHwEncr & 7]
		       , p->key.gKeyData.UnicastKeyEnabled ? "ena" : "-",
		       p->key.gKeyData.UnicastKeyEnabled ? ciphernames[p->key.
								       gKeyData.
								       UnicastKeyType
								       & 7] :
		       "-", p->key.gKeyData.MulticastKeyEnabled ? "ena" : "-",
		       p->key.gKeyData.MulticastKeyEnabled ? ciphernames[p->key.
									 gKeyData.
									 MulticastKeyType
									 & 7] :
		       "-", p->key.gKeyData.groupKeyIndex);
		if (p->key.gKeyData.UnicastKeyEnabled) {
			printk("PTK:      ");
			for (i = 0; i < 16; i++)
				printk(" %02x",
				       p->key.gKeyData.RSNPairwiseTempKey[i]);
			printk("\n");
			printk("PTK TxMIC: %08x %08x	TxIV: %08x %04x\n",
			       p->key.gKeyData.RSNPwkTxMICKey[0],
			       p->key.gKeyData.RSNPwkTxMICKey[1],
			       /*le32toh */ (p->key.gKeyData.TxIV32),
			       /*le16toh */ (p->key.gKeyData.TxIV16));
			printk("PTK RxMIC: %08x %08x	RxIV: %08x\n",
			       p->key.gKeyData.RSNPwkRxMICKey[0],
			       p->key.gKeyData.RSNPwkRxMICKey[1],
			       /*le32toh */ (p->key.gKeyData.RxIV32));
		}
		if (p->key.gKeyData.MulticastKeyEnabled) {
			printk("GTK:      ");
			for (i = 0; i < 16; i++)
				printk(" %02x",
				       p->key.gKeyData.RSNTempKey_group[i]);
			printk("\n");
			printk("GTK TxMIC: %08x %08x	TxIV: %08x %04x\n",
			       p->key.gKeyData.RSNTxMICKey_group[0],
			       p->key.gKeyData.RSNTxMICKey_group[1],
			       /*le32toh */ (p->key.gKeyData.groupTxIV32),
			       /*le16toh */ (p->key.gKeyData.groupTxIV16));
			printk("GTK RxMIC: %08x %08x	RxIV: %08x\n",
			       p->key.gKeyData.RSNRxMICKey_group[0],
			       p->key.gKeyData.RSNRxMICKey_group[1],
			       /*le32toh */ (p->key.gKeyData.groupRxIV32));
		}
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return 0;
#else
	// Not implemented
	return FAIL;
#endif //#ifdef SOC_W8964
}

BOOLEAN
wlFwGetHwStatsForWlStats(struct net_device * netdev,
			 struct iw_statistics * pStats)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	HostCmd_DS_802_11_GET_STAT *pCmd =
		(HostCmd_DS_802_11_GET_STAT *) & wlpptr->pCmdBuf[0];

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_GET_STAT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_GET_STAT));
	if (wlexecuteCommand(netdev, HostCmd_CMD_802_11_GET_STAT)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return FAIL;
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	pStats->discard.code = ENDIAN_SWAP32(pCmd->RxUndecryptableFrames);
	pStats->discard.fragment = ENDIAN_SWAP32(pCmd->RxFragErrors);
	pStats->discard.misc = 0;
	pStats->discard.nwid = 0;
	pStats->discard.retries = ENDIAN_SWAP32(pCmd->TxFailures);
	pStats->miss.beacon = 0;

	return TRUE;
}

#ifdef WTP_SUPPORT
BOOLEAN
wlFwGetWTPRadioStats(struct net_device * netdev, char *radiostats)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_GET_STAT *pCmd =
		(HostCmd_DS_802_11_GET_STAT *) & wlpptr->pCmdBuf[0];
	//struct net_device_stats  *stat = &(wlpptr->netDevStats);
	struct RadioStats *pStats = (struct RadioStats *)radiostats;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_GET_STAT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_GET_STAT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_GET_STAT));
	if (wlexecuteCommand(netdev, HostCmd_CMD_802_11_GET_STAT)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return FAIL;
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	pStats->RxOverrunErr = 6;	//ENDIAN_SWAP32(pCmd->RxOverflows);
	/*
	   pStats->RxMacCrcErr = ENDIAN_SWAP32(pCmd->RxFCSErrors);
	   pStats->RxWepErr = ENDIAN_SWAP32(pCmd->RxUndecryptableFrames);;
	   pStats->MaxRetries= 0;
	   pStats->RxAck= 0;
	   pStats->NoAck= 0;
	   pStats->NoCts= 0;
	   pStats->RxCts= 0;
	   pStats->TxRts= 0;
	   pStats->TxCts= 0;
	   pStats->TxUcFrags= 0;
	   pStats->Tries= 0;
	   pStats->TxMultRetries= 0;
	   pStats->RxUc= 0;
	   pStats->TxBroadcast= 0;
	   pStats->RxBroadcast= 0;
	   pStats->TxMgmt= 0;
	   pStats->TxCtrl= 0;
	   pStats->TxBeacon= 0;
	   pStats->TxProbeRsp= 0;
	   pStats->RxMgmt= 0;
	   pStats->RxCtrl= 0;
	   pStats->RxBeacon= 0;
	   pStats->RxProbeReq= 0;
	   pStats->DupFrag= 0;
	   pStats->RxFrag= 0;
	   pStats->RxAged= 0;
	   pStats->TxKb= stat->tx_bytes;
	   pStats->RxKb= stat->rx_bytes;
	   pStats->TxAggr= 0;
	   pStats->Jammed= 0;
	   pStats->TxConcats= 0;
	   pStats->RxConcats= 0;
	   pStats->TxHwWatchdog= 0;
	   pStats->TxSwWatchdog= 0;
	   pStats->NoAckPolicy= 0;
	   pStats->TxAged= 0;
	 */
	return TRUE;
}

#endif

int
wlFwHTGI(struct net_device *netdev, u_int32_t GIType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_HT_GUARD_INTERVAL *pCmd =
		(HostCmd_FW_HT_GUARD_INTERVAL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_HT_GUARD_INTERVAL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_HT_GUARD_INTERVAL);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_HT_GUARD_INTERVAL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP32(WL_SET);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	if (GIType == 0) {
		pCmd->GIType.LongGI = 1;
		pCmd->GIType.ShortGI = 1;
	} else if (GIType == 1) {
		pCmd->GIType.LongGI = 0;
		pCmd->GIType.ShortGI = 1;
	} else {
		pCmd->GIType.LongGI = 1;
		pCmd->GIType.ShortGI = 0;
	}
	pCmd->GIType.RESV = 0;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_HT_GUARD_INTERVAL));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_HT_GUARD_INTERVAL);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetRadio(struct net_device *netdev, u_int16_t mode, wlpreamble_e preamble)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_RADIO_CONTROL *pCmd =
		(HostCmd_DS_802_11_RADIO_CONTROL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "mode: %s,preamble: %i",
			 (mode == WL_DISABLE) ? "disable" : "enable", preamble);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_RADIO_CONTROL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_RADIO_CONTROL);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_RADIO_CONTROL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(WL_SET);
	pCmd->Control = ENDIAN_SWAP16(preamble);
	pCmd->RadioOn = ENDIAN_SWAP16(mode);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	if (mode == WL_DISABLE) {
		pCmd->Control = 0;
	}

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_RADIO_CONTROL));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_RADIO_CONTROL);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

void
BFMRconfigRxAnt(struct wlprivate *wlpptr, UINT8 RxAntTmp)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->BFMRinitDone) {
		if (vmacSta_p->BFMRconfig.rx_ant != RxAntTmp) {
			vmacSta_p->BFMRconfig.rx_ant = RxAntTmp;
			vmacSta_p->bBFMRconfigChanged = TRUE;
		}
	} else {
		vmacSta_p->BFMRconfig.rx_ant = RxAntTmp;
		vmacSta_p->BFMRinitstatus.rx_ant_init = 1;
	}
}

void
BFMRconfigTxAnt(struct wlprivate *wlpptr, UINT8 TxAntTmp)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->BFMRinitDone) {
		if (vmacSta_p->BFMRconfig.tx_ant != TxAntTmp) {
			vmacSta_p->BFMRconfig.tx_ant = TxAntTmp;
			vmacSta_p->bBFMRconfigChanged = TRUE;
		}
	} else {
		vmacSta_p->BFMRconfig.tx_ant = TxAntTmp;
		vmacSta_p->BFMRinitstatus.tx_ant_init = 1;
	}
}

int
wlFwSetAntenna(struct net_device *netdev, wlantennatype_e dirSet)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	UINT8 *mib_rxAntBitmap_p = mib->mib_rxAntBitmap;
	UINT8 *mib_txAntenna_p = mib->mib_txAntenna;
	UINT8 RxAntTmp, TxAntTmp;
	UINT8 Antenna = 0x0;

	HostCmd_DS_802_11_RF_ANTENNA *pCmd =
		(HostCmd_DS_802_11_RF_ANTENNA *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "will set %s antenna",
			 (dirSet == WL_ANTENNATYPE_RX) ? "RX" : "TX");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_RF_ANTENNA));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_RF_ANTENNA);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_RF_ANTENNA));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(dirSet);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

#ifdef SOC_W906X
	if (wlpptr->devid == SC5)
		Antenna = 0xff;
	else
#endif
		Antenna = 0xf;

	if (dirSet == WL_ANTENNATYPE_RX) {
		if ((*mib_rxAntBitmap_p != 0)) {
			pCmd->AntennaMode = ENDIAN_SWAP16(*mib_rxAntBitmap_p);	//(WL_ANTENNAMODE_RX);
			RxAntTmp = *mib_rxAntBitmap_p;
		} else {
			pCmd->AntennaMode = ENDIAN_SWAP16(Antenna);
			RxAntTmp = Antenna;
		}
		BFMRconfigRxAnt(wlpptr, RxAntTmp);
		printk("setting rxantenna 0x%x, 0x%x\n", *mib_rxAntBitmap_p,
		       RxAntTmp);

	} else {
		if (dirSet == WL_ANTENNATYPE_TX2) {
			pCmd->AntennaMode = ENDIAN_SWAP16(*mib->mib_txAntenna2);
			TxAntTmp = *mib->mib_txAntenna2;
		} else {
			printk("setting txantenna 0x%x, 0x%x\n",
			       *mib_txAntenna_p, Antenna);
			if (*mib_txAntenna_p != 0) {
				pCmd->AntennaMode =
					ENDIAN_SWAP16(*mib_txAntenna_p);
				TxAntTmp = *mib_txAntenna_p;
			} else {
				pCmd->AntennaMode = ENDIAN_SWAP16(Antenna);
				TxAntTmp = Antenna;
			}
		}
		BFMRconfigTxAnt(wlpptr, TxAntTmp);
	}

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_RF_ANTENNA));
	if (macMgmtMlme_DfsEnabled(netdev))
		mdelay(10);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_RF_ANTENNA);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER
int
wlFwSetCoexConfig(struct net_device *netdev, u8 * enable, u8 * gpioLevelDetect,
		  u8 * gpioLevelTrigger, u32 * gpioReqPin, u32 * gpioGrantPin,
		  u32 * gpioPriPin, u8 set)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_COEX_CONF *pCmd =
		(HostCmd_DS_802_11_COEX_CONF *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	if (WL_GET == set) {
		memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_COEX_CONF));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_COEX_CONF_ACCESS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_COEX_CONF));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->reserved = set;
		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_DS_802_11_COEX_CONF));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_COEX_CONF_ACCESS);
		if (SUCCESS == retval) {
			*enable = pCmd->enable;
			*gpioLevelDetect = pCmd->gpioLevelDetect;
			*gpioLevelTrigger = pCmd->gpioLevelTrigger;
			*gpioReqPin = ENDIAN_SWAP32(pCmd->gpioReqPin);
			*gpioGrantPin = ENDIAN_SWAP32(pCmd->gpioGrantPin);
			*gpioPriPin = ENDIAN_SWAP32(pCmd->gpioPriPin);
		}
	} else if (WL_SET == set) {
		memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_COEX_CONF));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_COEX_CONF_ACCESS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_COEX_CONF));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->reserved = set;
		pCmd->enable = *enable;
		pCmd->gpioLevelDetect = *gpioLevelDetect;
		pCmd->gpioLevelTrigger = *gpioLevelTrigger;
		pCmd->gpioReqPin = ENDIAN_SWAP32(*gpioReqPin);
		pCmd->gpioGrantPin = ENDIAN_SWAP32(*gpioGrantPin);
		pCmd->gpioPriPin = ENDIAN_SWAP32(*gpioPriPin);
		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_DS_802_11_COEX_CONF));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_COEX_CONF_ACCESS);
	} else {
	}			//reset
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif

#ifndef SOC_W906X
int
wlFwSetRTSRetry(struct net_device *netdev, int rts_retry)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_RTS_RETRY *pCmd =
		(HostCmd_DS_802_11_RTS_RETRY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	printk("%s(), RTS Retry: %i (0x%x)\n", __func__, rts_retry, rts_retry);
	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "RTS Retry: %i (0x%x)", rts_retry, rts_retry);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_RTS_RETRY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RTS_RETRY);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_RTS_RETRY));
	pCmd->Action = ENDIAN_SWAP16(WL_SET);
	pCmd->Retry = ENDIAN_SWAP16(rts_retry);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_RTS_THSD));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RTS_RETRY);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif /* #ifndef SOC_W906X */

int
wlFwSetRTSThreshold(struct net_device *netdev, int threshold)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_RTS_THSD *pCmd =
		(HostCmd_DS_802_11_RTS_THSD *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "RTS threshold: %i (0x%x)", threshold, threshold);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_RTS_THSD));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_RTS_THSD);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_RTS_THSD));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(WL_SET);
	pCmd->Threshold = ENDIAN_SWAP16(threshold);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_RTS_THSD));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_RTS_THSD);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetInfraMode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_INFRA_MODE *pCmd =
		(HostCmd_FW_SET_INFRA_MODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_INFRA_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_INFRA_MODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_INFRA_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_INFRA_MODE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_INFRA_MODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef SOC_W906X
#ifdef CLIENT_SUPPORT
int
wlFwSetBssForClientMode(struct net_device *netdev, wlfacilitate_e facility)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	HostCmd_BSS_START *pCmd = (HostCmd_BSS_START *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	int rateMask, rate_id;
	u_int8_t basic_rate_id = 0;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "AP bss %s",
			 (facility == WL_ENABLE) ? "enable" : "disable");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_BSS_START));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BSS_START);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_BSS_START));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Enable = ENDIAN_SWAP32(facility);
	pCmd->CmdHdr.macid = vmacSta_p->VMacEntry.macId;
	pCmd->Amsdu = *(mib->mib_amsdutx);
	pCmd->IntfFlag = INTF_STA_MODE;
	pCmd->qosEnabled = *(mib->QoSOptImpl);

	if (facility == WL_ENABLE) {
		rateMask = *(mib->BssBasicRateMask);
		for (rate_id = 0; rate_id < 14; rate_id++) {
			if (rateMask & 0x01)
				pCmd->BasicRate[basic_rate_id] =
					mib->StationConfig->
					OpRateSet[rate_id] & 0x7F;
			basic_rate_id++;
			if (basic_rate_id >= IEEEtypes_MAX_DATA_RATES)
				break;
			rateMask >>= 1;
		}
		pCmd->NumOfBasicRates = basic_rate_id;
		memcpy((void *)pCmd->MacAddr, (void *)netdev->dev_addr,
		       IEEEtypes_ADDRESS_SIZE);
	}
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_BSS_START));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_BSS_START);

	if (pCmd->Status)
		printk("wlFwSetAPBss::: bss %s failed with reason code %d  facility=0x%08x \n", (facility == WL_ENABLE) ? "start" : "stop", pCmd->Status, facility);
	else {
		if (facility == WL_ENABLE)
			SMAC_RX_ENABLE(wlpptr, mib, vmacSta_p->VMacEntry.macId);
		else
			SMAC_RX_DISABLE(wlpptr, mib,
					vmacSta_p->VMacEntry.macId);
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif
#endif /* #ifdef SOC_W906X */

extern UINT16 dfs_chirp_count_min;
extern UINT16 dfs_chirp_time_interval;
extern UINT16 dfs_pw_filter;
extern UINT16 dfs_min_pri_count;
extern UINT16 dfs_min_num_radar;

int
wlFwSetRadarDetection(struct net_device *netdev, UINT32 action)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
#ifndef SOC_W906X
	UINT8 chan = mib->PhyDSSSTable->CurrChan;
#endif
	UINT16 radarTypeCode = 0;

	HostCmd_802_11h_Detect_Radar *pCmd =
		(HostCmd_802_11h_Detect_Radar *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "AP radar detection enabled\n");
	/* First check if the region code is Japan and 5 GHz channel
	 * If so, assign radarTypeCode = 56 for 104 < chan < 140
	 * and assign radarTypeCode = 53 for 52 < chan < 64
	 */
#ifndef SOC_W906X
	/* not used in FW */
	if (*(mib->mib_regionCode) == DOMAIN_CODE_MKK &&
	    domainChannelValid(chan, FREQ_BAND_5GHZ)) {
		if (chan >= 52 && chan <= 64) {
			radarTypeCode = 53;
		} else if (chan >= 100 && chan <= 140) {
			radarTypeCode = 56;
		} else
			radarTypeCode = 0;
	} else if (*(mib->mib_regionCode) == DOMAIN_CODE_ETSI) {
		radarTypeCode = HostCmd_80211H_RADAR_TYPE_CODE_ETSI_151;
	}
#endif

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_802_11h_Detect_Radar));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11H_DETECT_RADAR);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_802_11h_Detect_Radar));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Action = ENDIAN_SWAP16(action);
	pCmd->RadarTypeCode = ENDIAN_SWAP16(radarTypeCode);

	pCmd->MinChirpCount = ENDIAN_SWAP16(dfs_chirp_count_min);
	pCmd->ChirpTimeIntvl = ENDIAN_SWAP16(dfs_chirp_time_interval);
	pCmd->PwFilter = ENDIAN_SWAP16(dfs_pw_filter);
	pCmd->MinNumRadar = ENDIAN_SWAP16(dfs_min_num_radar);
	pCmd->PriMinNum = ENDIAN_SWAP16(dfs_min_pri_count);
#ifdef SOC_W906X
	pCmd->EnablePrimary80MHz = mib->PhyDSSSTable->Chanflag.isDfsChan;
	pCmd->EnableSecond80MHz = mib->PhyDSSSTable->Chanflag.isDfsChan2;
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_802_11h_Detect_Radar));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11H_DETECT_RADAR);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef SOC_W906X
int
wlFwSetChannelSwitchIE(struct net_device *netdev, UINT16 nextChannel,
		       UINT16 secChan, UINT32 mode, UINT32 count,
		       CHNL_FLAGS Chanflag)
#else
int
wlFwSetChannelSwitchIE(struct net_device *netdev, UINT32 nextChannel,
		       UINT32 mode, UINT32 count, UINT32 FreqBand,
		       UINT32 ChnlWidth)
#endif
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef SOC_W906X
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
#endif
	HostCmd_SET_SWITCH_CHANNEL *pCmd =
		(HostCmd_SET_SWITCH_CHANNEL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "AP Channel To Switch to %d Mode :%d and Count :%d",
			 nextChannel, mode, count);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_SWITCH_CHANNEL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_SWITCH_CHANNEL);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_SWITCH_CHANNEL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Next11hChannel = ENDIAN_SWAP32(nextChannel);
	pCmd->Mode = ENDIAN_SWAP32(mode);
	pCmd->InitialCount = ENDIAN_SWAP32(count);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#ifdef  BARBADOS_DFS_TEST

	pCmd->dfs_test_mode = dfs_probability;
#else
	pCmd->dfs_test_mode = dfs_test_mode;
#endif

	/*Setting Chnlwidth &  ActPrimary same as in wlFwSetChannel */
#ifdef SOC_W906X
	pCmd->ChannelFlags.FreqBand = Chanflag.FreqBand;
	pCmd->ChannelFlags.ChnlWidth = Chanflag.ChnlWidth;
	pCmd->ChannelFlags.radiomode = Chanflag.radiomode;
	pCmd->Channel2 = secChan;

	if (Chanflag.ChnlWidth == CH_AUTO_WIDTH) {
		if (Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ) {
			pCmd->ChannelFlags.ChnlWidth = CH_40_MHz_WIDTH;
		} else {
			if ((*(mib->mib_ApMode) >= AP_MODE_11AC) &&
			    (*(mib->mib_ApMode) <= AP_MODE_5GHZ_Nand11AC))
				pCmd->ChannelFlags.ChnlWidth = CH_160_MHz_WIDTH;
			else
				pCmd->ChannelFlags.ChnlWidth = CH_40_MHz_WIDTH;
		}
	}
#else
	pCmd->ChannelFlags.FreqBand = FreqBand;
	pCmd->ChannelFlags.ChnlWidth = ChnlWidth;
#endif

	/*Get 11n HT ext channel offset of target channel */
	if ((pCmd->ChannelFlags.ChnlWidth == CH_40_MHz_WIDTH) ||
	    (pCmd->ChannelFlags.ChnlWidth == CH_80_MHz_WIDTH))
		pCmd->NextHTExtChnlOffset =
			macMgmtMlme_Get40MHzExtChannelOffset(pCmd->
							     Next11hChannel);
	else
		pCmd->NextHTExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

	/*Based on next channel HT ext offset, get ActPrimary */
	if (pCmd->NextHTExtChnlOffset == EXT_CH_ABOVE_CTRL_CH)
		pCmd->ChannelFlags.ActPrimary = ACT_PRIMARY_CHAN_0;
	else if (pCmd->NextHTExtChnlOffset == EXT_CH_BELOW_CTRL_CH)
		pCmd->ChannelFlags.ActPrimary = ACT_PRIMARY_CHAN_1;
	else
		pCmd->ChannelFlags.ActPrimary = ACT_PRIMARY_CHAN_0;

	if (pCmd->ChannelFlags.ChnlWidth == CH_80_MHz_WIDTH)
		pCmd->ChannelFlags.ActPrimary =
			macMgmtMlme_Get80MHzPrimaryChannelOffset(pCmd->
								 Next11hChannel);

	if (pCmd->ChannelFlags.ChnlWidth == CH_160_MHz_WIDTH)
		pCmd->ChannelFlags.ActPrimary =
			macMgmtMlme_Get160MHzPrimaryChannelOffset(pCmd->
								  Next11hChannel);
#ifdef MV_CPU_BE
	pCmd->ChannelFlags.u32_data =
		ENDIAN_SWAP32(pCmd->ChannelFlags.u32_data);
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SET_SWITCH_CHANNEL));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_SWITCH_CHANNEL);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetSpectrumMgmt(struct net_device *netdev, UINT32 spectrumMgmt)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_SPECTRUM_MGMT *pCmd =
		(HostCmd_SET_SPECTRUM_MGMT *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "Set Spectrum Management to %d", spectrumMgmt);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_SPECTRUM_MGMT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_SPECTRUM_MGMT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_SPECTRUM_MGMT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->SpectrumMgmt = ENDIAN_SWAP32(spectrumMgmt);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SET_SPECTRUM_MGMT));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_SPECTRUM_MGMT);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetPowerConstraint(struct net_device *netdev, UINT32 powerConstraint)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_POWER_CONSTRAINT *pCmd =
		(HostCmd_SET_POWER_CONSTRAINT *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	IEEEtypes_PowerConstraintElement_t PowerConstraintIE;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "Set power constraint to %d dB", powerConstraint);

	memset((UINT8 *) & PowerConstraintIE, 0,
	       sizeof(IEEEtypes_PowerConstraintElement_t));
	PowerConstraintIE.ElementId = PWR_CONSTRAINT;
	PowerConstraintIE.value = powerConstraint;
	PowerConstraintIE.Len = 1;

	macMgmtMlme_UpdateProbeRspBasicIes(wlpptr->vmacSta_p,
					   (UINT8 *) & PowerConstraintIE,
					   PowerConstraintIE.Len + 2);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_POWER_CONSTRAINT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_POWER_CONSTRAINT);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_SET_POWER_CONSTRAINT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->PowerConstraint = ENDIAN_SWAP32(powerConstraint);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SET_POWER_CONSTRAINT));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_POWER_CONSTRAINT);

	if (pCmd->VHTTransmitPowerEnvelopeElement.Len) {
		macMgmtMlme_UpdateProbeRspBasicIes(wlpptr->vmacSta_p,
						   (UINT8 *) & pCmd->
						   VHTTransmitPowerEnvelopeElement,
						   pCmd->
						   VHTTransmitPowerEnvelopeElement.
						   Len + 2);
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	return retval;
}

int
wlFwSetCountryCode(struct net_device *netdev, UINT32 domainCode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->Mib802dot11;
	//MIB_SPECTRUM_MGMT     *mib_SpectrumMagament_p=wlpptr->vmacSta_p->Mib802dot11->SpectrumMagament;
	HostCmd_SET_COUNTRY_INFO *pCmd =
		(HostCmd_SET_COUNTRY_INFO *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	DomainCountryInfo DomainInfo[1];
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	IEEEtypes_COUNTRY_IE_t CountryIE;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "Set  the country infor for :%x\n", domainCode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_COUNTRY_INFO));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_COUNTRY_CODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_COUNTRY_INFO));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	if (domainCode == 0) {
		pCmd->Action = HostCmd_ACT_GEN_DEL;
		memset(&pCmd->DomainInfo, 0, sizeof(DomainCountryInfo));
	} else {
		pCmd->Action = HostCmd_ACT_GEN_SET;
		bcn_reg_domain = domainCode;
		domainGetPowerInfo((UINT8 *) DomainInfo);

		if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ) {
			DomainInfo->GChannelLen = 0;
		} else {
			DomainInfo->AChannelLen = 0;
		}
		memcpy(&pCmd->DomainInfo, DomainInfo,
		       sizeof(DomainCountryInfo));

		memset((UINT8 *) & CountryIE, 0,
		       sizeof(IEEEtypes_COUNTRY_IE_t));
		CountryIE.ElemId = COUNTRY;
		CountryIE.CountryCode[0] = DomainInfo->CountryString[0];
		CountryIE.CountryCode[1] = DomainInfo->CountryString[1];
#ifdef MBO_SUPPORT
		if (mib->mib_mbo_enabled) {
			CountryIE.CountryCode[2] = 0x04;
			pCmd->DomainInfo.CountryString[2] = 0x04;
		} else
#endif /* MBO_SUPPORT */
			CountryIE.CountryCode[2] = DomainInfo->CountryString[2];

		if (DomainInfo->AChannelLen) {
			CountryIE.Len = DomainInfo->AChannelLen + 3;  /** include 3 byte of country code here **/
			memcpy((UINT8 *) (CountryIE.DomainEntry),
			       (UINT8 *) (DomainInfo->DomainEntryA),
			       DomainInfo->AChannelLen);
		} else {
			CountryIE.Len = DomainInfo->GChannelLen + 3;  /** include 3 byte of country code here **/
			memcpy((UINT8 *) (CountryIE.DomainEntry),
			       (UINT8 *) (DomainInfo->DomainEntryG),
			       DomainInfo->GChannelLen);
		}
		macMgmtMlme_UpdateProbeRspBasicIes(wlpptr->vmacSta_p,
						   (UINT8 *) & CountryIE,
						   CountryIE.Len + 2);
	}

	pCmd->Action = ENDIAN_SWAP32(pCmd->Action);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SET_COUNTRY_INFO));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_COUNTRY_CODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef IEEE80211K
int
wlFwSetRadioResourceMgmt(struct net_device *netdev, UINT8 rrm)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_RRM *pCmd = (HostCmd_SET_RRM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set Radio Resouce Mgmt to %d", rrm);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_RRM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RRM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_RRM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->rrm = ENDIAN_SWAP32(rrm);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_SET_RRM));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RRM);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetBcnChannelUtil(struct net_device *netdev, UINT8 ch_tril)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_CH_UTIL *pCmd =
		(HostCmd_SET_CH_UTIL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set Channel Utilization to %d", ch_tril);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_CH_UTIL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_CH_UTIL);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_CH_UTIL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->ch_util = ch_tril;
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_SET_CH_UTIL));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_CH_UTIL);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetQuiet(struct net_device *netdev, UINT8 enable, UINT8 period,
	     UINT16 duration, UINT16 offset, UINT16 offset1, UINT8 txStop_en)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_QUIET *pCmd = (HostCmd_SET_QUIET *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "Set Quiet to %d %d %d %d", enable, period, duration,
			 offset);

#if 1				//dbg
	printk("wlFwSetQuiet(): %d %d %d %d %d %d\n", enable, period, duration,
	       offset, offset1, txStop_en);
#endif

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_QUIET));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_QUIET);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_QUIET));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->enable = enable;
	pCmd->period = period;
	pCmd->duration = ENDIAN_SWAP16(duration);
	pCmd->offset = ENDIAN_SWAP16(offset);
	pCmd->offset1 = ENDIAN_SWAP16(offset1);
	pCmd->txStop_en = txStop_en;
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_SET_QUIET));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_QUIET);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	if (retval != SUCCESS) {
		printk("wlFwSetQuiet() ret = %d\n", retval);
	}

	return retval;
}
#endif

#ifdef WMM_AC_EDCA
int
wlFwSetBssLoadAac(struct net_device *netdev, UINT16 aac)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_BSS_LOAD_AAC *pCmd =
		(HostCmd_SET_BSS_LOAD_AAC *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set Bss Load Aac to %d", aac);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_BSS_LOAD_AAC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_BSS_LOAD_AAC);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_BSS_LOAD_AAC));
	pCmd->aac = ENDIAN_SWAP16(aac);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SET_BSS_LOAD_AAC));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_BSS_LOAD_AAC);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif

int
wlFwSetRegionCode(struct net_device *netdev, UINT16 regionCode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_REGIONCODE_INFO *pCmd =
		(HostCmd_SET_REGIONCODE_INFO *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_REGIONCODE_INFO));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_REGION_CODE);
	pCmd->regionCode = ENDIAN_SWAP16(domainGetRegulatory(regionCode));
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_SET_REGIONCODE_INFO));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_SET_REGIONCODE_INFO));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_REGION_CODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwGetNoiseLevel(struct net_device *netdev, UINT16 action, UINT8 * pNoise)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_GET_NOISE_Level *pCmd =
		(HostCmd_FW_GET_NOISE_Level *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_NOISE_Level));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_NOISE_LEVEL);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_NOISE_Level));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(action);

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_FW_GET_NOISE_Level));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_NOISE_LEVEL);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	*pNoise = pCmd->Noise;
	return retval;
}

#ifdef MRVL_WSC
int
wlFwSetWscIE(struct net_device *netdev, UINT16 ieType, WSC_COMB_IE_t * pWscIE)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_WSC_IE *pCmd = (HostCmd_SET_WSC_IE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	if (pWscIE == NULL)
		return retval;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_WSC_IE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_WSC_IE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_WSC_IE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->ieType = ENDIAN_SWAP16(ieType);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	memcpy(&pCmd->wscIE, pWscIE, sizeof(WSC_COMB_IE_t));

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd, sizeof(HostCmd_SET_WSC_IE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_WSC_IE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif // MRVL_WSC

#ifdef MRVL_WAPI
int
wlFwSetWapiIE(struct net_device *netdev, UINT16 ieType, WAPI_COMB_IE_t * pAPPIE)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_WAPI_IE *pCmd =
		(HostCmd_SET_WAPI_IE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	if (pAPPIE == NULL)
		return retval;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_WAPI_IE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_WAPI_IE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_WAPI_IE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->ieType = ENDIAN_SWAP16(ieType);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	memcpy(&pCmd->WAPIIE, pAPPIE, sizeof(WAPI_COMB_IE_t));

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd, sizeof(HostCmd_SET_WAPI_IE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_WAPI_IE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif // MRVL_WAPI

int
wlFwSetRate(struct net_device *netdev, wlrate_e rate)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_USE_FIXED_RATE *pCmd =
		(HostCmd_FW_USE_FIXED_RATE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	UINT8 mode;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_USE_FIXED_RATE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_FIXED_RATE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_USE_FIXED_RATE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	if (rate == 0)
		pCmd->Action = ENDIAN_SWAP32(HostCmd_ACT_NOT_USE_FIXED_RATE);
	else
		pCmd->Action = ENDIAN_SWAP32(HostCmd_ACT_GEN_SET);

	pCmd->MulticastRate = *(mib->mib_MulticastRate);
	pCmd->MultiRateTxType = *(mib->mib_MultiRateTxType);
	pCmd->ManagementRate = *(mib->mib_ManagementRate);

	if (*(mib->mib_enableFixedRateTx) == 2) {
		pCmd->AllowRateDrop =
			ENDIAN_SWAP32(FIXED_RATE_WITHOUT_AUTORATE_DROP);

		if (*(mib->mib_FixedRateTxType) == 0x4) {	//use rateinfo directly
			pCmd->FixedRateTable[0].FixRateTypeFlags.FixRateType =
				ENDIAN_SWAP32(0x4);
			pCmd->FixedRateTable[0].FixedRate =
				ENDIAN_SWAP32(*(mib->mib_txDataRateInfo));

		} else if (*(mib->mib_FixedRateTxType) == 0x2) {
			//fixed vht rate
			pCmd->FixedRateTable[0].FixRateTypeFlags.FixRateType =
				ENDIAN_SWAP32(0x2);
			pCmd->FixedRateTable[0].FixedRate =
				ENDIAN_SWAP32(*(mib->mib_txDataRateVHT));
		} else if (*(mib->mib_FixedRateTxType) == 0x1) {
			//fixed 11n rate
			pCmd->FixedRateTable[0].FixRateTypeFlags.FixRateType =
				ENDIAN_SWAP32(0x1);
			pCmd->FixedRateTable[0].FixedRate =
				ENDIAN_SWAP32(*(mib->mib_txDataRateN));
		} else {
			//legacy
			pCmd->FixedRateTable[0].FixRateTypeFlags.FixRateType =
				0;

			mode = *(mib->mib_FixedRateTxType) >> 4;
			if (mode == 0x2)
				pCmd->FixedRateTable[0].FixedRate =
					ENDIAN_SWAP32(*(mib->mib_txDataRateA));
			else if (mode == 0x1)
				pCmd->FixedRateTable[0].FixedRate =
					ENDIAN_SWAP32(*(mib->mib_txDataRateG));
			else
				pCmd->FixedRateTable[0].FixedRate =
					ENDIAN_SWAP32(*(mib->mib_txDataRate));
		}

		pCmd->EntryCount = ENDIAN_SWAP32(1);
		WLDBG_INFO(DBG_LEVEL_0, "%s rate at %i w/o auto drop",
			   *(mib->mib_FixedRateTxType) ? "HT" : "legacy",
			   *(mib->mib_FixedRateTxType) ? *(mib->
							   mib_txDataRateN) :
			   *(mib->mib_txDataRate));
	} else if (*(mib->mib_enableFixedRateTx) == 1) {
		UINT8 i;
		UINT32 RetryCount = 3;	//Allow Auto rate with drop totally to send 12 packets(11 retries);
		pCmd->AllowRateDrop =
			ENDIAN_SWAP32(FIXED_RATE_WITH_AUTO_RATE_DROP);
		pCmd->FixedRateTable[0].FixRateTypeFlags.FixRateType =
			ENDIAN_SWAP32(*(mib->mib_FixedRateTxType));
		pCmd->FixedRateTable[0].FixedRate =
			ENDIAN_SWAP32(*(mib->mib_FixedRateTxType) ?
				      *(mib->mib_txDataRateN) : *(mib->
								  mib_txDataRate));

		pCmd->EntryCount = ENDIAN_SWAP32(4);
		for (i = 0; i < 4; i++) {
			if (*(mib->mib_FixedRateTxType) == 2) {	//fixed 11ac rate with drop
				UINT32 vht_mcs = *(mib->mib_txDataRateVHT) - i;
				pCmd->FixedRateTable[i].FixRateTypeFlags.
					FixRateType = ENDIAN_SWAP32(2);
				if ((vht_mcs & 0xf) > 9) {
					vht_mcs = (vht_mcs & 0xf0) | 0x9;
				}
				pCmd->FixedRateTable[i].FixedRate =
					ENDIAN_SWAP32(vht_mcs);
			}
			pCmd->FixedRateTable[i].FixRateTypeFlags.
				RetryCountValid =
				ENDIAN_SWAP32(RETRY_COUNT_VALID);
			pCmd->FixedRateTable[i].RetryCount =
				ENDIAN_SWAP32(RetryCount);
		}

		WLDBG_INFO(DBG_LEVEL_0, "%s rate at %i w/ auto drop",
			   *(mib->mib_FixedRateTxType) ? "HT" : "legacy",
			   *(mib->mib_FixedRateTxType) ? *(mib->
							   mib_txDataRateN) :
			   *(mib->mib_txDataRate));
	} else {
		pCmd->AllowRateDrop =
			ENDIAN_SWAP32(FIXED_RATE_WITH_AUTO_RATE_DROP);
		WLDBG_INFO(DBG_LEVEL_0, "auto rate %i",
			   *(mib->mib_enableFixedRateTx));
	}
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_USE_FIXED_RATE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_FIXED_RATE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetSlotTime(struct net_device *netdev, wlslot_e slot)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_SLOT *pCmd =
		(HostCmd_FW_SET_SLOT *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "set slot: %s",
			 (slot == WL_SHORTSLOT) ? "short" : "long");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_SLOT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_SET_SLOT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_SLOT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(WL_SET);
	pCmd->Slot = slot;
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_SET_SLOT));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_SET_SLOT);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

static int
wlFwSettxpowers(struct net_device *netdev, UINT16 txpow[], UINT8 action,
		UINT16 ch, UINT16 band, UINT16 width, UINT16 sub_ch)
{
	int retval, i;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_TX_POWER *pCmd =
		(HostCmd_DS_802_11_TX_POWER *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_TX_POWER));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_TX_POWER);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_TX_POWER));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(action);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ch = ENDIAN_SWAP16(ch);
	pCmd->bw = ENDIAN_SWAP16(width);
	pCmd->band = ENDIAN_SWAP16(band);
	pCmd->sub_ch = ENDIAN_SWAP16(sub_ch);

	for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++)
		pCmd->PowerLevelList[i] = ENDIAN_SWAP16(txpow[i]);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_TX_POWER);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetTxPower(struct net_device *netdev, UINT8 flag, UINT32 powerLevel)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	UINT16 txpow[TX_POWER_LEVEL_TOTAL];
	int reduceVal = 0;
	int i, index, found = 0;
	MIB_802DOT11 *mibS = vmacSta_p->ShadowMib802dot11;
	MIB_802DOT11 *mibA = vmacSta_p->Mib802dot11;
	UINT16 tmp;

#ifdef PWRFRAC
	switch (*(mibS->mib_TxPwrFraction)) {
	case 0:
		reduceVal = 0;	/* Max */
		break;
	case 1:
		reduceVal = 2;	/* 75% -1.25db */
		break;
	case 2:
		reduceVal = 3;	/* 50% -3db */
		break;
	case 3:
		reduceVal = 6;	/* 25% -6db */
		break;

	default:
		reduceVal = *(mibS->mib_MaxTxPwr);	/* larger than case 3,  pCmd->MaxPowerLevel is min */
		break;
	}
#endif

	/* search tx power table if exist */
	for (index = 0; index < IEEE_80211_MAX_NUMBER_OF_CHANNELS; index++) {
		/* do nothing if table is not loaded */
		if (mibS->PhyTXPowerTable[index]->Channel == 0)
			break;

		if (mibS->PhyTXPowerTable[index]->Channel ==
		    mibS->PhyDSSSTable->CurrChan) {
			*(mibS->mib_CDD) = *(mibA->mib_CDD) =
				mibS->PhyTXPowerTable[index]->CDD;
			*(mibS->mib_txAntenna2) = *(mibA->mib_txAntenna2) =
				mibS->PhyTXPowerTable[index]->txantenna2;

			if (mibS->PhyTXPowerTable[index]->setcap)
				mibS->PhyDSSSTable->powinited = 0x01;
			else
				mibS->PhyDSSSTable->powinited = 0x02;

			for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
				if (mibS->PhyTXPowerTable[index]->setcap)
					mibS->PhyDSSSTable->maxTxPow[i] =
						mibS->PhyTXPowerTable[index]->
						TxPower[i];
				else
					mibS->PhyDSSSTable->targetPowers[i] =
						mibS->PhyTXPowerTable[index]->
						TxPower[i];
			}

			found = 1;
			break;
		}
	}

	if ((mibS->PhyDSSSTable->powinited & 1) == 0) {
		wlFwGettxpower(netdev, mibS->PhyDSSSTable->targetPowers,
			       mibS->PhyDSSSTable->CurrChan,
			       mibS->PhyDSSSTable->Chanflag.FreqBand,
			       mibS->PhyDSSSTable->Chanflag.ChnlWidth,
			       mibS->PhyDSSSTable->Chanflag.ExtChnlOffset);
		mibS->PhyDSSSTable->powinited |= 1;
	}
	if ((mibS->PhyDSSSTable->powinited & 2) == 0) {
		wlFwGettxpower(netdev, mibS->PhyDSSSTable->maxTxPow,
			       mibS->PhyDSSSTable->CurrChan,
			       mibS->PhyDSSSTable->Chanflag.FreqBand,
			       mibS->PhyDSSSTable->Chanflag.ChnlWidth,
			       mibS->PhyDSSSTable->Chanflag.ExtChnlOffset);
		mibS->PhyDSSSTable->powinited |= 2;
	}
	for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
		if (found) {
			if ((mibS->PhyTXPowerTable[index]->setcap)
			    && (mibS->PhyTXPowerTable[index]->TxPower[i] >
				mibS->PhyDSSSTable->maxTxPow[i]))
				tmp = mibS->PhyDSSSTable->maxTxPow[i];
			else
				tmp = mibS->PhyTXPowerTable[index]->TxPower[i];
		} else {
			if (mibS->PhyDSSSTable->targetPowers[i] >
			    mibS->PhyDSSSTable->maxTxPow[i])
				tmp = mibS->PhyDSSSTable->maxTxPow[i];
			else
				tmp = mibS->PhyDSSSTable->targetPowers[i];
		}
		txpow[i] = ((tmp - reduceVal) > 0) ? (tmp - reduceVal) : 0;
	}
	return wlFwSettxpowers(netdev, txpow, HostCmd_ACT_GEN_SET_LIST,
			       mibS->PhyDSSSTable->CurrChan,
			       mibS->PhyDSSSTable->Chanflag.FreqBand,
			       mibS->PhyDSSSTable->Chanflag.ChnlWidth,
			       mibS->PhyDSSSTable->Chanflag.ExtChnlOffset);
}

int
wlFwGettxpower(struct net_device *netdev, UINT16 * powlist, UINT16 ch,
	       UINT16 band, UINT16 width, UINT16 sub_ch)
{
	int i, retval;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_802_11_TX_POWER *pCmd =
		(HostCmd_DS_802_11_TX_POWER *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_TX_POWER));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_TX_POWER);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_TX_POWER));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Action = ENDIAN_SWAP16(HostCmd_ACT_GEN_GET_LIST);
	pCmd->ch = ENDIAN_SWAP16(ch);
	pCmd->bw = ENDIAN_SWAP16(width);
	pCmd->band = ENDIAN_SWAP16(band);
	pCmd->sub_ch = ENDIAN_SWAP16(sub_ch);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_TX_POWER);
	if (retval == 0) {
		for (i = 0; i < MWL_MAX_TXPOWER_ENTRIES; i++) {
			powlist[i] =
				(UINT8) ENDIAN_SWAP16(pCmd->PowerLevelList[i]);
		}
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetTxPowerClientScan(struct net_device *netdev, UINT8 flag,
			 UINT32 powerLevel, UINT16 channel)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;

	HostCmd_DS_802_11_RF_TX_POWER *pCmd =
		(HostCmd_DS_802_11_RF_TX_POWER *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_MaxTxPwr_p = mib->mib_MaxTxPwr;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "powerlevel: %i", powerLevel);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_802_11_RF_TX_POWER));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_802_11_RF_TX_POWER);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_802_11_RF_TX_POWER));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP16(flag);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	if (flag == HostCmd_ACT_GEN_SET) {
		if (powerLevel < 30) {
			pCmd->SupportTxPowerLevel =
				ENDIAN_SWAP16(WL_TX_POWERLEVEL_LOW);
		} else if ((powerLevel >= 30) && (powerLevel < 60)) {
			pCmd->SupportTxPowerLevel =
				ENDIAN_SWAP16(WL_TX_POWERLEVEL_MEDIUM);
		} else {
			pCmd->SupportTxPowerLevel =
				ENDIAN_SWAP16(WL_TX_POWERLEVEL_HIGH);
		}
	} else if (flag == HostCmd_ACT_GEN_SET_LIST) {
		UINT8 i;
		UINT8 chan = channel;
		UINT8 ChanBw = PhyDSSSTable->Chanflag.ChnlWidth;

		if (chan <= 14) {	/* BG case and Channel 14 has been forced to 20M in wlset_freq() */
			if ((ChanBw == CH_40_MHz_WIDTH) ||
			    (ChanBw == CH_AUTO_WIDTH)) {
				/* Only for 40M, also auto bw is set 40M currently in wlFwSetChannel() */
				if (PhyDSSSTable->Chanflag.ExtChnlOffset ==
				    EXT_CH_BELOW_CTRL_CH) {
					if (chan > 4)
						chan -= 4;
				}
			}
			for (i = 0; i < 4; i++) {
				if ((ChanBw == CH_40_MHz_WIDTH) ||
				    (ChanBw == CH_AUTO_WIDTH)) {
					if (chan > 9)
						pCmd->PowerLevelList[i] =
							mib->
							PowerTagetRateTable40M[(chan - 5) * 4 + i];
					else
						pCmd->PowerLevelList[i] =
							mib->
							PowerTagetRateTable40M[(chan - 1) * 4 + i];
				} else
					pCmd->PowerLevelList[i] =
						mib->
						PowerTagetRateTable20M[(chan -
									1) * 4 +
								       i];
#ifdef PWRFRAC
				if (i == 0) {	/* The first is max */
					if (pCmd->PowerLevelList[i] <
					    *mib_MaxTxPwr_p)
						*mib_MaxTxPwr_p =
							pCmd->PowerLevelList[i];
					//printk("mib_MaxTxPwr %d chan %d\n", *mib_MaxTxPwr_p, chan);
				}
#endif
				pCmd->PowerLevelList[i] =
					ENDIAN_SWAP16(pCmd->PowerLevelList[i]);
			}

		} else {	/* A case */
			// Todo
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return SUCCESS;
		}
	} else {
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_802_11_RF_TX_POWER));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_802_11_RF_TX_POWER);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
int
wlFwSetMcast(struct net_device *netdev, struct netdev_hw_addr *mcAddr)
#else
int
wlFwSetMcast(struct net_device *netdev, struct dev_mc_list *mcAddr)
#endif
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int retval = FAIL;
	unsigned int num = 0;
	HostCmd_DS_MAC_MULTICAST_ADR *pCmd =
		(HostCmd_DS_MAC_MULTICAST_ADR *) & wlpptr->pCmdBuf[0];

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
	if (netdev_mc_count(netdev) == 0)
#else
	if (netdev->mc_count == 0)
#endif
	{
		WLDBG_WARNING(DBG_LEVEL_0, "set of 0 multicast addresses");
		return SUCCESS;
	}

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_MAC_MULTICAST_ADR));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_MAC_MULTICAST_ADR);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_MAC_MULTICAST_ADR));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
	netdev_for_each_mc_addr(mcAddr, netdev) {
		memcpy(&pCmd->MACList[(num * ETH_ALEN)], mcAddr->addr,
		       ETH_ALEN);
		num++;
		if (num >= HostCmd_MAX_MCAST_ADRS) {
			break;
		}
	}
#else
	for (; num < netdev->mc_count; mcAddr = mcAddr->next) {
		memcpy(&pCmd->MACList[(num * ETH_ALEN)], &mcAddr->dmi_addr[0],
		       ETH_ALEN);
		num++;
		if (num >= HostCmd_MAX_MCAST_ADRS) {
			break;
		}
	}
#endif

	pCmd->NumOfAdrs = ENDIAN_SWAP16(num);
	pCmd->Action = ENDIAN_SWAP16(0xffff);
	WLDBG_DUMP_DATA(DBG_LEVEL_0,
			(void *)pCmd, sizeof(HostCmd_DS_MAC_MULTICAST_ADR));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_MAC_MULTICAST_ADR);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef RX_REPLAY_DETECTION

static inline void
DOT11_RESETPN(u8 * dst)
{
	(*(u16 *) & dst[0]) = 0;
	(*(u32 *) & dst[2]) = 0;
}

static int
pn_replay_update_key_index(struct wlprivate *wlpptr, UINT8 * macAddr,
			   UINT8 keyType, UINT8 keyIndex)
{
	rx_queue_t *rq;
	UINT32 tid, retCode = 0;
	extStaDb_StaInfo_t *pStaInfo;
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->Mib802dot11;

	if (*(mib->mib_STAMode))
		macAddr =
			GetParentStaBSSID(wlpptr->vmacSta_p->VMacEntry.
					  phyHwMacIndx);

	pStaInfo =
		extStaDb_GetStaInfo(wlpptr->vmacSta_p,
				    (IEEEtypes_MacAddr_t *) macAddr,
				    STADB_DONT_UPDATE_AGINGTIME);

	if (pStaInfo) {
		if (keyType == ENCR_KEY_FLAG_GTK_RX_KEY)
			rq = &pStaInfo->pn->mcRxQueues[0];
		else {
			rq = &pStaInfo->pn->ucRxQueues[0];
			pStaInfo->pn->ucMgmtRxQueues.InxPN = keyIndex;
			DOT11_RESETPN(pStaInfo->pn->ucMgmtRxQueues.
				      RxPN[keyIndex]);
		}

		for (tid = 0; tid < MAX_TID + 1; tid++) {
			rq->InxPN = keyIndex;
			DOT11_RESETPN(rq->RxPN[keyIndex]);
			rq++;
		}
	} else {
		retCode = 1;
	}
	return retCode;
}
#endif

#ifdef SOC_W906X
int
wlFwSetSecurityKey(struct net_device *netdev, UINT16 action, UINT8 type,
		   UINT8 * pMacAddr, UINT8 keyIndex, UINT16 keyLen,
		   UINT32 keyInfo, UINT8 * pKeyParam)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_UPDATE_SECURITY_KEY *pCmd =
		(HostCmd_FW_UPDATE_SECURITY_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_SECURITY_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_SECURITY_KEY);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_SECURITY_KEY));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Action = ENDIAN_SWAP16(action);

	memcpy(pCmd->Macaddr, pMacAddr, sizeof(pCmd->Macaddr));

	pCmd->KeyType = type;
	pCmd->KeyIndex = keyIndex;
	pCmd->KeyInfo = ENDIAN_SWAP32(keyInfo);

	if (action != ACT_DEL) {
		switch (type) {
		case KEY_TYPE_ID_WEP:
			{
				WEP_TYPE_KEY *pKey = (WEP_TYPE_KEY *) pKeyParam;

				memcpy(pCmd->Key.Wep.KeyMaterial,
				       pKey->KeyMaterial, keyLen);
			}
			break;
		case KEY_TYPE_ID_TKIP:
			{
				TKIP_TYPE_KEY *pKey =
					(TKIP_TYPE_KEY *) pKeyParam;

				memcpy(pCmd->Key.Tkip.KeyMaterial,
				       pKey->KeyMaterial,
				       sizeof(pCmd->Key.Tkip.KeyMaterial));
				memcpy(pCmd->Key.Tkip.TxMicKey, pKey->TxMicKey,
				       sizeof(pCmd->Key.Tkip.TxMicKey));
				memcpy(pCmd->Key.Tkip.RxMicKey, pKey->RxMicKey,
				       sizeof(pCmd->Key.Tkip.RxMicKey));

				pCmd->Key.Tkip.Rsc.low = 0;
				pCmd->Key.Tkip.Rsc.high = 0;
				pCmd->Key.Tkip.Tsc.low =
					ENDIAN_SWAP16(pKey->Tsc.low);
				pCmd->Key.Tkip.Tsc.high =
					ENDIAN_SWAP32(pKey->Tsc.high);
				keyLen +=
					sizeof(pCmd->Key.Tkip.TxMicKey) +
					sizeof(pCmd->Key.Tkip.RxMicKey);
#ifdef RX_REPLAY_DETECTION
				pn_replay_update_key_index(wlpptr, pMacAddr,
							   (keyInfo &
							    ENCR_KEY_FLAG_GTK_RX_KEY),
							   keyIndex);
#endif
			}
			break;
		case KEY_TYPE_ID_CCMP:
		case KEY_TYPE_ID_GCMP:
			{
				AES_TYPE_KEY *pKey = (AES_TYPE_KEY *) pKeyParam;

				memcpy(pCmd->Key.Aes.KeyMaterial,
				       pKey->KeyMaterial, keyLen);
#ifdef RX_REPLAY_DETECTION
				pn_replay_update_key_index(wlpptr, pMacAddr,
							   (keyInfo &
							    ENCR_KEY_FLAG_GTK_RX_KEY),
							   keyIndex);
#endif
			}
			break;
		case KEY_TYPE_ID_WAPI:
			{
				WAPI_TYPE_KEY *pKey =
					(WAPI_TYPE_KEY *) pKeyParam;

				memcpy(pCmd->Key.Wapi.PN, pKey->PN,
				       WAPI_PN_LENGTH);
				memcpy(pCmd->Key.Wapi.KeyMaterial,
				       pKey->KeyMaterial, keyLen);
				memcpy(pCmd->Key.Wapi.MicKeyMaterial,
				       pKey->MicKeyMaterial,
				       sizeof(pCmd->Key.Wapi.MicKeyMaterial));
			}
			break;
		default:
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return 1;
		}
	}
	pCmd->KeyLen = ENDIAN_SWAP16(keyLen);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_CMD_UPDATE_SECURITY_KEY Action=%d KeyType=%d KeyLen=%d keyInfo=0x%08x",
		   action, type, keyLen, keyInfo);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_SECURITY_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_SECURITY_KEY);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#else

#endif /* #ifdef SOC_W906X */

int
wlFwSetWep(struct net_device *netdev, u_int8_t * staaddr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	UINT32 keyIndex;
	UINT16 keyLen;
	int retval = FAIL;
#ifdef SOC_W906X
	UINT32 keyInfo;
	WEP_TYPE_KEY param;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->PrivInvoked)
		return SUCCESS;

	if (mib->AuthAlg->Type == AUTH_SHARED_KEY) {
		/* RESTRICTED */
		if (!*(mib->mib_strictWepShareKey))
			mib->AuthAlg->Type = AUTH_OPEN_OR_SHARED_KEY;
	}

	if (mib->WepDefaultKeys[*(mib->mib_defaultkeyindex)].WepType == 2)
		keyLen = WEP_KEY_104_BIT_LEN;
	else
		keyLen = WEP_KEY_40_BIT_LEN;

	retval = SUCCESS;
	for (keyIndex = 0; keyIndex < 4; keyIndex++) {
		keyInfo = 0;
		if (keyIndex == *(mib->mib_defaultkeyindex))
			keyInfo |= ENCR_KEY_FLAG_WEP_TXKEY;

		memcpy(param.KeyMaterial,
		       mib->WepDefaultKeys[keyIndex].WepDefaultKeyValue,
		       keyLen);
		retval +=
			wlFwSetSecurityKey(netdev, ACT_SET, KEY_TYPE_ID_WEP,
					   staaddr, keyIndex, keyLen, keyInfo,
					   (UINT8 *) & param);
	}
#else
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->PrivInvoked)
		return SUCCESS;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

	if (mib->AuthAlg->Type == AUTH_SHARED_KEY) {
		/* RESTRICTED */
		if (!*(mib->mib_strictWepShareKey))
			mib->AuthAlg->Type = AUTH_OPEN_OR_SHARED_KEY;
	}

	if (mib->WepDefaultKeys[*(mib->mib_defaultkeyindex)].WepType == 2)
		keyLen = ENDIAN_SWAP16(WEP_KEY_104_BIT_LEN);
	else
		keyLen = ENDIAN_SWAP16(WEP_KEY_40_BIT_LEN);
	for (keyIndex = 0; keyIndex < 4; keyIndex++) {
		memset(pCmd, 0x00,
		       sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
		pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KEY_TYPE_ID_WEP);
		if (keyIndex == *(mib->mib_defaultkeyindex)) {
			pCmd->ActionType =
				ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
			pCmd->KeyParam.KeyInfo =
				ENDIAN_SWAP32(ENCR_KEY_FLAG_WEP_TXKEY);
		} else
			pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetKey);

		pCmd->KeyParam.KeyIndex = ENDIAN_SWAP32(keyIndex);
		pCmd->KeyParam.KeyLen = keyLen;
		memcpy(pCmd->KeyParam.Key.WepKey.KeyMaterial,
		       mib->WepDefaultKeys[keyIndex].WepDefaultKeyValue,
		       pCmd->KeyParam.KeyLen);
		memcpy(&pCmd->KeyParam.Macaddr[0], staaddr, 6);
		WLDBG_INFO(DBG_LEVEL_0,
			   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET Len = %d pCmd->KeyParam = %d\n",
			   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
			   sizeof(pCmd->KeyParam));
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));

		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_UPDATE_ENCRYPTION);
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
#endif /* #ifdef SOC_W906X */
	return retval;
}

#ifndef SOC_W906X
int
wlFwSetWpaTkipMode(struct net_device *netdev, u_int8_t * staaddr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_UPDATE_ENCRYPTION *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->RSNEnabled)
		return SUCCESS;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionEnableHWEncryption);
	pCmd->ActionData[0] = EncrTypeTkip;
	WLDBG_INFO(DBG_LEVEL_0, "wlFwSetWpaTkipMode::: mode=%d\n",
		   pCmd->ActionData[0]);
	memcpy(&pCmd->macaddr[0], staaddr, 6);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#endif /* #infdef SOC_W906X */

int
wlFwSetWpaWpa2PWK(struct net_device *netdev, extStaDb_StaInfo_t * StaInfo_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	int retval = FAIL;
#ifdef SOC_W906X
	UINT32 keyType = KEY_TYPE_ID_TKIP;
	UINT32 keyLen = TK_SIZE;
	UINT32 keyInfo = 0;
	TKIP_TYPE_KEY tkipParam;
	AES_TYPE_KEY aesParam;
	UINT8 *pParam;
	UINT8 OuiType = CIPHER_OUI_TYPE_NONE;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->RSNEnabled)
		return SUCCESS;

	if ((StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221 &&
	     StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17] == 2)
	    || (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 48 &&
		StaInfo_p->keyMgmtStateInfo.RsnIEBuf[13] == 2)) {

		pParam = (UINT8 *) & tkipParam;

		keyType = KEY_TYPE_ID_TKIP;
		keyInfo =
			ENCR_KEY_FLAG_PTK | ENCR_KEY_FLAG_TSC_VALID |
			ENCR_KEY_FLAG_MICKEY_VALID;

		memcpy(tkipParam.KeyMaterial,
		       StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1,
		       MAX_ENCR_KEY_LENGTH);
		memcpy(tkipParam.TxMicKey,
		       StaInfo_p->keyMgmtStateInfo.RSNPwkTxMICKey,
		       MIC_KEY_LENGTH);
		memcpy(tkipParam.RxMicKey,
		       StaInfo_p->keyMgmtStateInfo.RSNPwkRxMICKey,
		       MIC_KEY_LENGTH);
		tkipParam.Rsc.low = 0;
		tkipParam.Rsc.high = 0;
		tkipParam.Tsc.low = StaInfo_p->keyMgmtStateInfo.TxIV16;
		tkipParam.Tsc.high = StaInfo_p->keyMgmtStateInfo.TxIV32;
	} else if ((StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221 &&
		    StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17] == 4)
		   || (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 48 &&
		       isAes4RsnValid(StaInfo_p->keyMgmtStateInfo.
				      RsnIEBuf[13]))) {

		pParam = (UINT8 *) & aesParam;
		OuiType = StaInfo_p->keyMgmtStateInfo.RsnIEBuf[13];

		keyInfo = ENCR_KEY_FLAG_PTK;
		if (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221)
			OuiType = StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17];

		keymgmt_aesInfoGet(OuiType, &keyType, &keyLen);

		memcpy(aesParam.KeyMaterial,
		       StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1, keyLen);
	} else {
		return retval;
	}
	wlFwSetSecurityKey(netdev, ACT_SET, keyType,
			   StaInfo_p->Addr, 0, keyLen, keyInfo, pParam);

#ifdef CONFIG_IEEE80211W
	StaInfo_p->ptkCipherOuiType = OuiType;
#endif

#else
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	//HostCmd_FW_UPDATE_ENCRYPTION *pCmd2 = (HostCmd_FW_UPDATE_ENCRYPTION *) &wlpptr->pCmdBuf[0];
	UINT8 OuiType = CIPHER_OUI_TYPE_NONE;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->RSNEnabled)
		return SUCCESS;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	if ((StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221 &&
	     StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17] == 2)
	    || (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 48 &&
		StaInfo_p->keyMgmtStateInfo.RsnIEBuf[13] == 2)) {
		// TKIP
		OuiType = CIPHER_OUI_TYPE_TKIP;
		pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KEY_TYPE_ID_TKIP);
		pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_PAIRWISE |
						       ENCR_KEY_FLAG_TSC_VALID |
						       ENCR_KEY_FLAG_MICKEY_VALID);
		pCmd->KeyParam.KeyIndex = 0;
		pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(sizeof(TKIP_TYPE_KEY));
		memcpy(pCmd->KeyParam.Key.TkipKey.KeyMaterial,
		       StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1,
		       MAX_ENCR_KEY_LENGTH);
		memcpy(pCmd->KeyParam.Key.TkipKey.TkipTxMicKey,
		       StaInfo_p->keyMgmtStateInfo.RSNPwkTxMICKey,
		       MIC_KEY_LENGTH);
		memcpy(pCmd->KeyParam.Key.TkipKey.TkipRxMicKey,
		       StaInfo_p->keyMgmtStateInfo.RSNPwkRxMICKey,
		       MIC_KEY_LENGTH);
		pCmd->KeyParam.Key.TkipKey.TkipRsc.low = 0;
		pCmd->KeyParam.Key.TkipKey.TkipRsc.high = 0;
		pCmd->KeyParam.Key.TkipKey.TkipTsc.low = ENDIAN_SWAP16(StaInfo_p->keyMgmtStateInfo.TxIV16);	//= 0;
		pCmd->KeyParam.Key.TkipKey.TkipTsc.high = ENDIAN_SWAP32(StaInfo_p->keyMgmtStateInfo.TxIV32);	//= = 0;
		memcpy(pCmd->KeyParam.Macaddr, StaInfo_p->Addr, 6);
		WLDBG_INFO(DBG_LEVEL_0,
			   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WPA TKIP Len = %d pCmd->KeyParam = %d",
			   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
			   sizeof(pCmd->KeyParam));
	} else if ((StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221 &&
		    StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17] == 4)
		   || (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 48 &&
		       isAes4RsnValid(StaInfo_p->keyMgmtStateInfo.
				      RsnIEBuf[13]))) {
		UINT32 keyTypeId, keyLen;
		// AES
		if (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221)
			OuiType = StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17];
		else
			OuiType = StaInfo_p->keyMgmtStateInfo.RsnIEBuf[13];

		keymgmt_aesInfoGet(OuiType, &keyTypeId, &keyLen);

		// AES
		pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(keyTypeId);
		pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_PAIRWISE);
		pCmd->KeyParam.KeyIndex = 0;	// NA for wpa
		pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(keyLen);

		memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
		       StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1, keyLen);
		memcpy(pCmd->KeyParam.Macaddr, StaInfo_p->Addr, 6);
		WLDBG_INFO(DBG_LEVEL_0,
			   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WPA AES Key Type=%d Len=%d \n",
			   keyTypeId, keyLen);
	} else {
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	memcpy(pCmd->KeyParam.Macaddr, StaInfo_p->Addr, 6);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);
#ifdef CONFIG_IEEE80211W
	StaInfo_p->ptkCipherOuiType = OuiType;
#endif

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
#endif /* #ifdef SOC_W906X */
	return retval;
}

#ifndef SOC_W906X
#ifdef MRVL_WAPI
int
wlFwSetWapiKey(struct net_device *netdev, struct wlreq_wapi_key *wapi_key,
	       int groupkey)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	if (groupkey)
		pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
	else
		pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetKey);

	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));

	pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KEY_TYPE_ID_WAPI);
	pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_PAIRWISE);
	pCmd->KeyParam.KeyIndex = wapi_key->ik_keyid;
	pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(sizeof(WAPI_TYPE_KEY));

	memcpy(pCmd->KeyParam.Key.WapiKey.KeyMaterial,
	       &(wapi_key->ik_keydata[0]), KEY_LEN);
	memcpy(pCmd->KeyParam.Key.WapiKey.MicKeyMaterial,
	       &(wapi_key->ik_keydata[16]), KEY_LEN);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WAPI Len = %d pCmd->KeyParam = %d",
		   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
		   sizeof(pCmd->KeyParam));

	memcpy(pCmd->KeyParam.Macaddr, wapi_key->ik_macaddr, 6);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	return retval;
}
#endif

int
keyMgmtCleanGroupKey(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeRemoveKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = 0;
	pCmd->KeyParam.KeyInfo =
		ENDIAN_SWAP32(ENCR_KEY_FLAG_RXGROUPKEY |
			      ENCR_KEY_FLAG_TXGROUPKEY);
	pCmd->KeyParam.KeyIndex = 0;	// NA for wpa
	pCmd->KeyParam.KeyLen = 0;
	memcpy(pCmd->KeyParam.Macaddr, &vmacSta_p->macStaAddr[0], 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET Remove GTK\n");
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetWpaTkipGroupK(struct net_device *netdev, UINT8 index)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->RSNEnabled)
		return SUCCESS;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KEY_TYPE_ID_TKIP);
	pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_TXGROUPKEY |
					       ENCR_KEY_FLAG_MICKEY_VALID |
					       ENCR_KEY_FLAG_TSC_VALID);
	pCmd->KeyParam.KeyIndex = ENDIAN_SWAP32(index);
	pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(sizeof(TKIP_TYPE_KEY));
	memcpy(pCmd->KeyParam.Key.TkipKey.KeyMaterial,
	       mib->mib_MrvlRSN_GrpKey->EncryptKey, MAX_ENCR_KEY_LENGTH);
	memcpy(pCmd->KeyParam.Key.TkipKey.TkipTxMicKey,
	       mib->mib_MrvlRSN_GrpKey->TxMICKey, MIC_KEY_LENGTH);
	memcpy(pCmd->KeyParam.Key.TkipKey.TkipRxMicKey,
	       mib->mib_MrvlRSN_GrpKey->RxMICKey, MIC_KEY_LENGTH);
	pCmd->KeyParam.Key.TkipKey.TkipRsc.low = 0;
	pCmd->KeyParam.Key.TkipKey.TkipRsc.high = 0;
	pCmd->KeyParam.Key.TkipKey.TkipTsc.low = ENDIAN_SWAP16(mib->mib_MrvlRSN_GrpKey->g_IV16);	//= 0;
	pCmd->KeyParam.Key.TkipKey.TkipTsc.high = ENDIAN_SWAP32(mib->mib_MrvlRSN_GrpKey->g_IV32);	// = 0;
	memcpy(pCmd->KeyParam.Macaddr, &vmacSta_p->macStaAddr[0], 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET Len = %d pCmd->KeyParam = %d",
		   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
		   sizeof(pCmd->KeyParam));
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#endif /* #ifndef SOC_W906X */

int
wlFwSetWpaGroupK_rx(struct net_device *netdev, wlreq_key * wk)
{
	int retval = FAIL;
#ifdef SOC_W906X
	UINT8 keyType;
	TKIP_TYPE_KEY tkipParam;
	AES_TYPE_KEY aesParam;
	UINT8 *pParam = (UINT8 *) & aesParam;

	switch (wk->ik_type) {
	case WL_CIPHER_TKIP:
		pParam = (UINT8 *) & tkipParam;
		keyType = KEY_TYPE_ID_TKIP;
		memcpy(tkipParam.KeyMaterial, &wk->ik_keydata[0],
		       MAX_ENCR_KEY_LENGTH);
		memcpy(tkipParam.TxMicKey, &wk->ik_keydata[16], MIC_KEY_LENGTH);
		memcpy(tkipParam.RxMicKey, &wk->ik_keydata[24], MIC_KEY_LENGTH);
		tkipParam.Rsc.low = 0;
		tkipParam.Rsc.high = 0;
		tkipParam.Tsc.low = wk->ik_keytsc << 48;
		tkipParam.Tsc.high = wk->ik_keytsc >> 32;
		break;
	case WL_CIPHER_CCMP:
	case WL_CIPHER_CCMP_256:
		keyType = KEY_TYPE_ID_CCMP;
		memcpy(aesParam.KeyMaterial, &wk->ik_keydata[0], wk->ik_keylen);
		break;
	case WL_CIPHER_GCMP:
	case WL_CIPHER_GCMP_256:
		keyType = KEY_TYPE_ID_GCMP;
		memcpy(aesParam.KeyMaterial, &wk->ik_keydata[0], wk->ik_keylen);
		break;
	default:
		printk("unknown key type \n");
		return FAIL;
	}

	wlFwSetSecurityKey(netdev, ACT_SET, keyType, wk->ik_macaddr,
			   wk->ik_keyix, wk->ik_keylen, ENCR_KEY_FLAG_RXONLY,
			   pParam);
#else
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	UINT16 KeyTypeId;
	unsigned long flags;
	BOOLEAN bUnknown = FALSE;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->RSNEnabled)
		return SUCCESS;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	switch (wk->ik_type) {
	case WL_CIPHER_TKIP:
		KeyTypeId = KEY_TYPE_ID_TKIP;
		memcpy(pCmd->KeyParam.Key.TkipKey.KeyMaterial,
		       &wk->ik_keydata[0], MAX_ENCR_KEY_LENGTH);
		memcpy(pCmd->KeyParam.Key.TkipKey.TkipTxMicKey,
		       &wk->ik_keydata[16], MIC_KEY_LENGTH);
		memcpy(pCmd->KeyParam.Key.TkipKey.TkipRxMicKey,
		       &wk->ik_keydata[24], MIC_KEY_LENGTH);
		pCmd->KeyParam.Key.TkipKey.TkipRsc.low = 0;
		pCmd->KeyParam.Key.TkipKey.TkipRsc.high = 0;
		pCmd->KeyParam.Key.TkipKey.TkipTsc.low = ENDIAN_SWAP16(wk->ik_keytsc << 48);	//= 0;
		pCmd->KeyParam.Key.TkipKey.TkipTsc.high = ENDIAN_SWAP32(wk->ik_keytsc >> 32);	// = 0;                      
		break;
	case WL_CIPHER_CCMP:
		KeyTypeId = KEY_TYPE_ID_AES;
		memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
		       &wk->ik_keydata[0], TK_SIZE);
		break;
	case WL_CIPHER_GCMP:
		KeyTypeId = KEY_TYPE_ID_GCMP_128;
		memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
		       &wk->ik_keydata[0], TK_SIZE);
		break;
	case WL_CIPHER_CCMP_256:
		KeyTypeId = KEY_TYPE_ID_CCMP_256;
		memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
		       &wk->ik_keydata[0], TK_SIZE_MAX);
		break;
	case WL_CIPHER_GCMP_256:
		KeyTypeId = KEY_TYPE_ID_GCMP_256;
		memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
		       &wk->ik_keydata[0], TK_SIZE_MAX);
		break;

	default:
		bUnknown = TRUE;
		break;
	}
	if (bUnknown) {
		printk("unknown key type \n");
		return FAIL;
	}
	pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KeyTypeId);
	pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_RXGROUPKEY |
					       ENCR_KEY_FLAG_MICKEY_VALID |
					       ENCR_KEY_FLAG_TSC_VALID);
	pCmd->KeyParam.KeyIndex = ENDIAN_SWAP32((UINT8) wk->ik_keyix);
	pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(wk->ik_keylen);

	memcpy(pCmd->KeyParam.Macaddr, wk->ik_macaddr, 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET Len = %d pCmd->KeyParam = %d",
		   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
		   sizeof(pCmd->KeyParam));
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	printk("set rx mcast\n");
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
#endif /* #ifdef SOC_W906X */
	return retval;
}

#ifndef SOC_W906X
int
wlFwSetWpaAesMode(struct net_device *netdev, u_int8_t * staaddr, UINT8 ouiType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_UPDATE_ENCRYPTION *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionEnableHWEncryption);
	pCmd->ActionData[0] = keymgmt_aesModeGet(ouiType);
	memcpy(&pCmd->macaddr[0], staaddr, 6);
	WLDBG_INFO(DBG_LEVEL_0, "wlFwSetWpaAesMode::: set security mode %d\n",
		   pCmd->ActionData[0]);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetWpaAesGroupK(struct net_device *netdev, UINT8 index, UINT8 ouiType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	UINT32 keyTypeId, keyLen;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	if (!mib->Privacy->RSNEnabled)
		return SUCCESS;
	keymgmt_aesInfoGet(ouiType, &keyTypeId, &keyLen);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(keyTypeId);
	pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_TXGROUPKEY);
	pCmd->KeyParam.KeyIndex = ENDIAN_SWAP32(index);	// NA for wpa
	pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(keyLen);

	memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
	       mib->mib_MrvlRSN_GrpKey->EncryptKey, keyLen);
	memcpy(pCmd->KeyParam.Macaddr, &vmacSta_p->macStaAddr[0], 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WPA AES Group Key Len=%d Type=%d",
		   keyLen, keyTypeId);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef WPA_STA
int
wlFwSetWpaWpa2PWK_STA(struct net_device *netdev, extStaDb_StaInfo_t * StaInfo_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	//HostCmd_FW_UPDATE_ENCRYPTION *pCmd2 = (HostCmd_FW_UPDATE_ENCRYPTION *) &wlpptr->pCmdBuf[0];
	int retval = FAIL;
	UINT8 OuiType = CIPHER_OUI_TYPE_NONE;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	//if (!mib->Privacy->RSNEnabled)
	//      return SUCCESS;
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = bss_num;	//wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	if ((StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221 &&
	     StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17] == 2)
	    || (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 48 &&
		StaInfo_p->keyMgmtStateInfo.RsnIEBuf[13] == 2)) {
		// TKIP
		OuiType = CIPHER_OUI_TYPE_TKIP;
		pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KEY_TYPE_ID_TKIP);
		pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_PAIRWISE |
						       ENCR_KEY_FLAG_TSC_VALID |
						       ENCR_KEY_FLAG_MICKEY_VALID);
		pCmd->KeyParam.KeyIndex = 0;
		pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(sizeof(TKIP_TYPE_KEY));
		memcpy(pCmd->KeyParam.Key.TkipKey.KeyMaterial,
		       StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1,
		       MAX_ENCR_KEY_LENGTH);
		memcpy(pCmd->KeyParam.Key.TkipKey.TkipTxMicKey,
		       StaInfo_p->keyMgmtStateInfo.RSNPwkTxMICKey,
		       MIC_KEY_LENGTH);
		memcpy(pCmd->KeyParam.Key.TkipKey.TkipRxMicKey,
		       StaInfo_p->keyMgmtStateInfo.RSNPwkRxMICKey,
		       MIC_KEY_LENGTH);
		pCmd->KeyParam.Key.TkipKey.TkipRsc.low = 0;
		pCmd->KeyParam.Key.TkipKey.TkipRsc.high = 0;
		pCmd->KeyParam.Key.TkipKey.TkipTsc.low = ENDIAN_SWAP16(StaInfo_p->keyMgmtStateInfo.TxIV16);	//= 0;
		pCmd->KeyParam.Key.TkipKey.TkipTsc.high = ENDIAN_SWAP32(StaInfo_p->keyMgmtStateInfo.TxIV32);	//= = 0;
		WLDBG_INFO(DBG_LEVEL_0,
			   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WPA TKIP Len = %d pCmd->KeyParam = %d",
			   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
			   sizeof(pCmd->KeyParam));
	} else if ((StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221 &&
		    StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17] == 4)
		   || (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 48 &&
		       isAes4RsnValid(StaInfo_p->keyMgmtStateInfo.
				      RsnIEBuf[13]))) {
		UINT32 keyTypeId, keyLen;
		// AES
		if (StaInfo_p->keyMgmtStateInfo.RsnIEBuf[0] == 221)
			OuiType = StaInfo_p->keyMgmtStateInfo.RsnIEBuf[17];
		else
			OuiType = StaInfo_p->keyMgmtStateInfo.RsnIEBuf[13];

		keymgmt_aesInfoGet(OuiType, &keyTypeId, &keyLen);

		pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(keyTypeId);
		pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_PAIRWISE);
		pCmd->KeyParam.KeyIndex = 0;	// NA for wpa
		pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(keyLen);

		memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial,
		       StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1, keyLen);
		WLDBG_INFO(DBG_LEVEL_0,
			   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WPA AES Len = %d pCmd->KeyParam = %d",
			   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
			   sizeof(pCmd->KeyParam));
	} else {
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	memcpy(pCmd->KeyParam.Macaddr, StaInfo_p->Addr, 6);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

#ifdef CONFIG_IEEE80211W
	StaInfo_p->ptkCipherOuiType = OuiType;
#endif
	return retval;
}

int
wlFwSetWpaAesMode_STA(struct net_device *netdev, u_int8_t * staaddr,
		      u_int8_t ouiType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_UPDATE_ENCRYPTION *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.macid = bss_num;	//wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionEnableHWEncryption);
	pCmd->ActionData[0] = keymgmt_aesModeGet(ouiType);
	memcpy(&pCmd->macaddr[0], staaddr, 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "wlFwSetWpaAesMode_STA::: set security mode %d\n",
		   pCmd->ActionData[0]);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetWpaAesGroupK_STA(struct net_device *netdev,
			UINT8 * macStaAddr_p,
			UINT8 * key_p, UINT8 index, UINT8 ouiType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	UINT32 keyTypeId, keyLen;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	keymgmt_aesInfoGet(ouiType, &keyTypeId, &keyLen);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = bss_num;	//wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(keyTypeId);
	pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_TXGROUPKEY);
	pCmd->KeyParam.KeyIndex = ENDIAN_SWAP32(index);	// NA for wpa
	pCmd->KeyParam.KeyLen = ENDIAN_SWAP16(keyLen);

	memcpy(pCmd->KeyParam.Key.AesKey.KeyMaterial, key_p, keyLen);
	memcpy(pCmd->KeyParam.Macaddr, macStaAddr_p, 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET WPA AES Group Key Len= %d Type= %d",
		   keyLen, keyTypeId);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetWpaTkipGroupK_STA(struct net_device *netdev,
			 UINT8 * macStaAddr_p,
			 UINT8 * key_p,
			 UINT16 keyLength,
			 UINT8 * rxMicKey_p,
			 UINT16 rxKeyLength,
			 UINT8 * txMicKey_p,
			 UINT16 txKeyLength,
			 ENCR_TKIPSEQCNT TkipTsc, UINT8 keyIndex)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	pCmd->CmdHdr.macid = bss_num;	//wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionTypeSetGroupKey);
	pCmd->KeyParam.Length = ENDIAN_SWAP16(sizeof(pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = ENDIAN_SWAP16(KEY_TYPE_ID_TKIP);
	pCmd->KeyParam.KeyInfo = ENDIAN_SWAP32(ENCR_KEY_FLAG_TXGROUPKEY |
					       ENCR_KEY_FLAG_MICKEY_VALID |
					       ENCR_KEY_FLAG_TSC_VALID);
	pCmd->KeyParam.KeyIndex = ENDIAN_SWAP32(keyIndex);	//index;
	pCmd->KeyParam.KeyLen =
		ENDIAN_SWAP16(keyLength + txKeyLength + rxKeyLength +
			      2 * sizeof(ENCR_TKIPSEQCNT));

	memcpy(pCmd->KeyParam.Key.TkipKey.KeyMaterial, key_p, keyLength);
	memcpy(pCmd->KeyParam.Key.TkipKey.TkipTxMicKey, txMicKey_p,
	       txKeyLength);
	memcpy(pCmd->KeyParam.Key.TkipKey.TkipRxMicKey, rxMicKey_p,
	       rxKeyLength);

	pCmd->KeyParam.Key.TkipKey.TkipRsc.low = 0;
	pCmd->KeyParam.Key.TkipKey.TkipRsc.high = 0;
	pCmd->KeyParam.Key.TkipKey.TkipTsc.low = ENDIAN_SWAP16(TkipTsc.low);	//= 0;
	pCmd->KeyParam.Key.TkipKey.TkipTsc.high = ENDIAN_SWAP32(TkipTsc.high);	// = 0;
	memcpy(pCmd->KeyParam.Macaddr, macStaAddr_p, 6);

	WLDBG_INFO(DBG_LEVEL_0,
		   "HostCmd_FW_UPDATE_ENCRYPTION_KEY_SET Len = %d pCmd->KeyParam = %d",
		   sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY),
		   sizeof(pCmd->KeyParam));
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetWpaTkipMode_STA(struct net_device *netdev, u_int8_t * staaddr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_UPDATE_ENCRYPTION *pCmd =
		(HostCmd_FW_UPDATE_ENCRYPTION *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	pCmd->CmdHdr.macid = bss_num;	//wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ActionType = ENDIAN_SWAP32(EncrActionEnableHWEncryption);
	pCmd->ActionData[0] = EncrTypeTkip;
	WLDBG_INFO(DBG_LEVEL_0, "wlFwSetWpaTkipMode_STA::: mode=%d\n",
		   pCmd->ActionData[0]);
	memcpy(&pCmd->macaddr[0], staaddr, 6);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_UPDATE_ENCRYPTION));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_ENCRYPTION);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#endif /* WPA_STA */
#endif /* #ifndef SOC_W906X */

#ifdef SINGLE_DEV_INTERFACE
int
wlFwSetMacAddr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_SET_MAC *pCmd = (HostCmd_DS_SET_MAC *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_SET_MAC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MAC_ADDR);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_SET_MAC));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#ifdef CLIENT_SUPPORT
	pCmd->MacType = ENDIAN_SWAP16(WL_MAC_TYPE_PRIMARY_CLIENT);
#endif
	memcpy(&pCmd->MacAddr[0], netdev->dev_addr, ETH_ALEN);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_DS_SET_MAC));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_MAC_ADDR);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif
int
wlFwRemoveMacAddr(struct net_device *netdev, UINT8 * macAddr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_SET_MAC *pCmd = (HostCmd_DS_SET_MAC *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_SET_MAC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_DEL_MAC_ADDR);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_SET_MAC));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	memcpy(&pCmd->MacAddr[0], macAddr, ETH_ALEN);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_DS_SET_MAC));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_DEL_MAC_ADDR);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef CLIENT_SUPPORT
int
wlFwSetMacAddr_Client(struct net_device *netdev, UINT8 * macAddr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_SET_MAC *pCmd = (HostCmd_DS_SET_MAC *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_SET_MAC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MAC_ADDR);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_SET_MAC));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#ifdef CLIENT_SUPPORT
#ifdef CLIENTONLY
	pCmd->MacType = ENDIAN_SWAP16(WL_MAC_TYPE_PRIMARY_CLIENT);	//WL_MAC_TYPE_SECONDARY_CLIENT;
#else
	pCmd->MacType = ENDIAN_SWAP16(WL_MAC_TYPE_SECONDARY_CLIENT);
#endif
#if NUMOFAPS == 1
	pCmd->MacType = ENDIAN_SWAP16(WL_MAC_TYPE_PRIMARY_CLIENT);	//WL_MAC_TYPE_SECONDARY_CLIENT;
#endif
#endif
	memcpy(&pCmd->MacAddr[0], macAddr, ETH_ALEN);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_DS_SET_MAC));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_MAC_ADDR);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif /* CLIENT_SUPPORT */
enum {
	IEEE80211_ELEMID_SSID = 0,
	IEEE80211_ELEMID_RATES = 1,
	IEEE80211_ELEMID_FHPARMS = 2,
	IEEE80211_ELEMID_DSPARMS = 3,
	IEEE80211_ELEMID_CFPARMS = 4,
	IEEE80211_ELEMID_TIM = 5,
	IEEE80211_ELEMID_IBSSPARMS = 6,
	IEEE80211_ELEMID_COUNTRY = 7,
	IEEE80211_ELEMID_CHALLENGE = 16,
	IEEE80211_ELEMID_ERP = 42,
	IEEE80211_ELEMID_RSN = 48,
	IEEE80211_ELEMID_XRATES = 50,
	IEEE80211_ELEMID_TPC = 150,
	IEEE80211_ELEMID_CCKM = 156,
	IEEE80211_ELEMID_VENDOR = 221,
};

int
wlFwSetApBeacon(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	HostCmd_DS_AP_BEACON *pCmd =
		(HostCmd_DS_AP_BEACON *) & wlpptr->pCmdBuf[0];
	u_int8_t *basicRates = &pCmd->StartCmd.BssBasicRateSet[0];
	u_int8_t *opRates = &pCmd->StartCmd.OpRateSet[0];
	u_int16_t capInfo = HostCmd_CAPINFO_DEFAULT;
	int retval = FAIL;
	IbssParams_t *ibssParamSet;
	CfParams_t *cfParamSet;
	DsParams_t *phyDsParamSet;
	int currRate = 0;
	int rateMask;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
#ifdef SOC_W906X
	IEEEtypes_SsIdElement_t *ssid_p;
#endif
	unsigned long flags;
	unsigned int ssid_len = 0;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_AP_BEACON));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_AP_BEACON);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_AP_BEACON));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = vmacSta_p->VMacEntry.macId;

	memcpy(pCmd->StartCmd.StaMacAddr, netdev->dev_addr,
	       sizeof(IEEEtypes_MacAddr_t));
	ssid_len = strlen(&(mib->StationConfig->DesiredSsId[0]));

	if (*(mib->mib_broadcastssid) && (ssid_len <= IEEEtypes_SSID_SIZE))
		memcpy(&pCmd->StartCmd.SsId[0],
		       &(mib->StationConfig->DesiredSsId[0]), ssid_len);
#ifdef SOC_W906X
	if (*(mib->mib_broadcastssid) && (ssid_len <= IEEEtypes_SSID_SIZE)) {
		ssid_p = (IEEEtypes_SsIdElement_t *)
			wl_kmalloc(strlen(&(mib->StationConfig->DesiredSsId[0]))
				   + sizeof(IEEEtypes_InfoElementHdr_t),
				   GFP_ATOMIC);
		ssid_p->ElementId = IEEE80211_ELEMID_SSID;
		ssid_p->Len = strlen(&(mib->StationConfig->DesiredSsId[0]));
		memcpy(&ssid_p->SsId, &(mib->StationConfig->DesiredSsId[0]),
		       ssid_len);
		macMgmtMlme_UpdateProbeRspBasicIes(vmacSta_p, (UINT8 *) ssid_p,
						   sizeof
						   (IEEEtypes_InfoElementHdr_t)
						   + ssid_p->Len);
		update_nontxd_bssid_profile_ssid(vmacSta_p, ssid_p);
		wl_kfree(ssid_p);
	}
#endif

	pCmd->StartCmd.BssType = 1;	// 0xffee; /* INFRA: 8bit */
	pCmd->StartCmd.BcnPeriod = ENDIAN_SWAP16(*(mib->mib_BcnPeriod));
	pCmd->StartCmd.DtimPeriod = mib->StationConfig->DtimPeriod;	/* 8bit */

	ibssParamSet = &pCmd->StartCmd.SsParamSet.IbssParamSet;
	ibssParamSet->ElementId = IEEE80211_ELEMID_IBSSPARMS;
	ibssParamSet->Len = sizeof(ibssParamSet->AtimWindow);
	ibssParamSet->AtimWindow = ENDIAN_SWAP16(0);

	cfParamSet = &pCmd->StartCmd.SsParamSet.CfParamSet;
	cfParamSet->ElementId = IEEE80211_ELEMID_CFPARMS;
	cfParamSet->Len = sizeof(cfParamSet->CfpCnt) +
		sizeof(cfParamSet->CfpPeriod) +
		sizeof(cfParamSet->CfpMaxDuration) +
		sizeof(cfParamSet->CfpDurationRemaining);
	cfParamSet->CfpCnt = 0;	/* 8bit */
	cfParamSet->CfpPeriod = 2;	/* 8bit */
	cfParamSet->CfpMaxDuration = ENDIAN_SWAP16(0);
	cfParamSet->CfpDurationRemaining = ENDIAN_SWAP16(0);

	phyDsParamSet = &pCmd->StartCmd.PhyParamSet.DsParamSet;
	phyDsParamSet->ElementId = IEEE80211_ELEMID_DSPARMS;
	phyDsParamSet->Len = sizeof(phyDsParamSet->CurrentChan);
	phyDsParamSet->CurrentChan = PhyDSSSTable->CurrChan;
#ifdef SOC_W906X
	macMgmtMlme_UpdateProbeRspBasicIes(vmacSta_p, (UINT8 *) phyDsParamSet,
					   sizeof(DsParams_t));
#endif

	pCmd->StartCmd.ProbeDelay = ENDIAN_SWAP16(10);

	capInfo |= HostCmd_CAPINFO_ESS;
	if (mib->StationConfig->mib_preAmble == PREAMBLE_SHORT ||
	    mib->StationConfig->mib_preAmble == PREAMBLE_AUTO_SELECT) {
		capInfo |= HostCmd_CAPINFO_SHORT_PREAMBLE;
	}
#ifdef MRVL_WAPI
	if (mib->Privacy->PrivInvoked || mib->Privacy->WAPIEnabled)
#else
	if (mib->Privacy->PrivInvoked)
#endif
	{
		capInfo |= HostCmd_CAPINFO_PRIVACY;
	} else {
		if (mib->Privacy->RSNEnabled) {
			InitThisStaRsnIE(vmacSta_p);

			if (!mib->RSNConfigWPA2->WPA2OnlyEnabled) {
				if (vmacSta_p->Mib802dot11->thisStaRsnIE->
				    PwsKeyCnt[0] > 1) {
					/* In mixed mode, if pairwise key > 1, Add mix WPA_IE in RsnMixedIE */
					AddRSN_IE(vmacSta_p,
						  (IEEEtypes_RSN_IE_t *) &
						  pCmd->RsnMixedIE);
#ifdef SOC_W906X
					macMgmtMlme_UpdateProbeRspBasicIes
						(vmacSta_p,
						 (UINT8 *) & pCmd->RsnMixedIE,
						 pCmd->RsnMixedIE.Len + 2);
#endif
				} else {
					AddRSN_IE(vmacSta_p,
						  (IEEEtypes_RSN_IE_t *) &
						  pCmd->StartCmd.RsnIE);
#ifdef SOC_W906X
					macMgmtMlme_UpdateProbeRspBasicIes
						(vmacSta_p,
						 (UINT8 *) & pCmd->StartCmd.
						 RsnIE,
						 pCmd->StartCmd.RsnIE.Len + 2);
#endif
				}
			}
			capInfo |= HostCmd_CAPINFO_PRIVACY;
		}
	}
	if (*(mib->QoSOptImpl) && !wfa_11ax_pf) {
		InitWMEParamElem(vmacSta_p);
		AddWMEParam_IE((WME_param_elem_t *) & pCmd->StartCmd.WMMParam);
#ifdef SOC_W906X
		macMgmtMlme_UpdateProbeRspBasicIes(vmacSta_p,
						   (UINT8 *) & pCmd->StartCmd.
						   WMMParam,
						   sizeof(WME_param_elem_t));
#endif
	}
#ifdef AP_WPA2
	if (mib->RSNConfigWPA2->WPA2Enabled ||
	    mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		if (mib->RSNConfigWPA2->WPA2Enabled &&
		    !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
			AddRSN_IEWPA2MixedMode(vmacSta_p,
					       (IEEEtypes_RSN_IE_WPA2MixedMode_t
						*) & pCmd->StartCmd.Rsn48IE);
#ifdef SOC_W906X
			macMgmtMlme_UpdateProbeRspBasicIes(vmacSta_p,
							   (UINT8 *) & pCmd->
							   StartCmd.Rsn48IE,
							   pCmd->StartCmd.
							   Rsn48IE.Len + 2);
#endif
		} else {
			AddRSN_IEWPA2(vmacSta_p,
				      (IEEEtypes_RSN_IE_WPA2_t *) & pCmd->
				      StartCmd.Rsn48IE);
			macMgmtMlme_UpdateProbeRspBasicIes(vmacSta_p,
							   (UINT8 *) & pCmd->
							   StartCmd.Rsn48IE,
							   pCmd->StartCmd.
							   Rsn48IE.Len + 2);
		}
	}
#endif

#ifdef IEEE80211K
	if (*(mib->mib_rrm)) {
		capInfo |= HostCmd_CAPINFO_RRM;
	}
#endif

	if (*(mib->mib_shortSlotTime)) {
		capInfo |= HostCmd_CAPINFO_SHORT_SLOT;
	}
	pCmd->StartCmd.CapInfo = ENDIAN_SWAP16(capInfo);
#ifdef SOC_W906X
	update_nontxd_bssid_profile_cap(vmacSta_p, capInfo);
	update_nontxd_bssid_profile_bssidIdx(vmacSta_p);
#endif
#ifdef SOC_W906X
	macMgmtMlme_UpdateProbeRspInfo(vmacSta_p, pCmd->StartCmd.BcnPeriod,
				       pCmd->StartCmd.CapInfo);
#endif
#ifdef BRS_SUPPORT

	rateMask = *(mib->BssBasicRateMask);
	for (currRate = 0; currRate < 14; currRate++) {
		if (rateMask & 0x01) {
			*basicRates++ =
				mib->StationConfig->OpRateSet[currRate] & 0x7F;
			//printk("ap8xLnxFwcmd: basic rate %d \n", (mib->StationConfig->OpRateSet[currRate] & 0x7F));
		}
		rateMask >>= 1;
	}

	rateMask = *(mib->BssBasicRateMask) | *(mib->NotBssBasicRateMask);
	for (currRate = 0; currRate < 14; currRate++) {
		if (rateMask & 0x01) {
			if (mib->StationConfig->OpRateSet[currRate] != 0)
				*opRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7F;
			//printk("ap8xLnxFwcmd: rate %d \n", (mib->StationConfig->OpRateSet[currRate] & 0x7F));
		}
		rateMask >>= 1;
	}

#else
	switch (*(mib->mib_ApMode)) {
	case AP_MODE_B_ONLY:
		for (currRate = 0; currRate < 4; currRate++) {
			*basicRates++ =
				mib->StationConfig->OpRateSet[currRate] & 0x7f;
		}
		for (currRate = 0; currRate < 4; currRate++) {
			if (mib->StationConfig->OpRateSet[currRate] != 0) {
				*opRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7f;
			}
		}
		break;

	case AP_MODE_G_ONLY:
		for (currRate = 0; currRate < 14; currRate++) {
			if (mib->StationConfig->OpRateSet[currRate] & 0x80)
				*basicRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7f;
		}
		for (currRate = 0; currRate < 14; currRate++) {
			if (mib->StationConfig->OpRateSet[currRate] != 0) {
				*opRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7f;
			}
		}
		break;

	case AP_MODE_A_ONLY:
		for (currRate = 0; currRate < 14; currRate++) {
			if (mib->StationConfig->OpRateSet[currRate] & 0x80)
				*basicRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7f;
		}

		for (currRate = 0; currRate < 8; currRate++) {
			if (mib->StationConfig->OpRateSet[currRate + 4] != 0) {
				*opRates++ =
					mib->StationConfig->OpRateSet[currRate +
								      4] & 0x7f;
			}
		}
		break;

	case AP_MODE_N_ONLY:
		if (PhyDSSSTable->CurrChan <= 14) {
			/* For 2.4G */
			for (currRate = 0; currRate < 4; currRate++) {
				*basicRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7f;
			}

			for (currRate = 0; currRate < 14; currRate++) {
				if (mib->StationConfig->OpRateSet[currRate] !=
				    0) {
					*opRates++ =
						mib->StationConfig->
						OpRateSet[currRate] & 0x7f;
				}
			}
		} else {
			/* For 5G */
			for (currRate = 0; currRate < 14; currRate++) {
				if (mib->StationConfig->
				    OpRateSet[currRate] & 0x80)
					*basicRates++ =
						mib->StationConfig->
						OpRateSet[currRate] & 0x7f;
			}

			for (currRate = 0; currRate < 8; currRate++) {
				if (mib->StationConfig->
				    OpRateSet[currRate + 4] != 0) {
					*opRates++ =
						mib->StationConfig->
						OpRateSet[currRate + 4] & 0x7f;
				}
			}
		}
		break;
	case AP_MODE_MIXED:
	default:
		if (*(mib->mib_ApMode) != AP_MODE_AandN &&
		    *(mib->mib_ApMode) != AP_MODE_5GHZ_Nand11AC
#ifdef SOC_W906X
		    && *(mib->mib_ApMode) != AP_MODE_5GHZ_ACand11AX
#endif
			) {
			/* For 2.4G */
			for (currRate = 0; currRate < 4; currRate++) {
				*basicRates++ =
					mib->StationConfig->
					OpRateSet[currRate] & 0x7f;
			}

			for (currRate = 0; currRate < 14; currRate++) {
				if (mib->StationConfig->OpRateSet[currRate] !=
				    0) {
					*opRates++ =
						mib->StationConfig->
						OpRateSet[currRate] & 0x7f;
				}
			}
		} else {
			/* For 5G */
			for (currRate = 0; currRate < 14; currRate++) {
				if (mib->StationConfig->
				    OpRateSet[currRate] & 0x80)
					*basicRates++ =
						mib->StationConfig->
						OpRateSet[currRate] & 0x7f;
			}

			for (currRate = 0; currRate < 8; currRate++) {
				if (mib->StationConfig->
				    OpRateSet[currRate + 4] != 0) {
					*opRates++ =
						mib->StationConfig->
						OpRateSet[currRate + 4] & 0x7f;
				}
			}
		}
		break;
	}
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_AP_BEACON));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_AP_BEACON);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetAid(struct net_device *netdev, u_int8_t * bssId, u_int16_t assocId)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_AID *pCmd = (HostCmd_FW_SET_AID *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "bssid: %s, association ID: %i", mac_display(bssId),
			 assocId);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_AID));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_AID);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_AID));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->AssocID = ENDIAN_SWAP16(assocId);
	memcpy(&pCmd->MacAddr[0], bssId, 6);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_SET_AID));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_AID);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

void
BFMRconfigChanBw(struct wlprivate *wlpptr, UINT8 ChnlWidth, UINT8 ExtChnlOffset,
		 UINT8 channel)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	UINT8 BFMRconfigbw;

	if (ChnlWidth == CH_80_MHz_WIDTH) {
		BFMRconfigbw = 6;
	} else if (ChnlWidth == CH_40_MHz_WIDTH) {
		if (ExtChnlOffset == EXT_CH_ABOVE_CTRL_CH) {
			BFMRconfigbw = 2;
		} else {
			BFMRconfigbw = 1;
		}
	} else if (ChnlWidth == CH_20_MHz_WIDTH) {
		BFMRconfigbw = 0;
	} else {		//unknown default to 20MHz
		BFMRconfigbw = 0;
	}
	if (vmacSta_p->BFMRinitDone) {
		if (vmacSta_p->BFMRconfig.chan != channel) {
			vmacSta_p->BFMRconfig.chan = channel;
			vmacSta_p->bBFMRconfigChanged = TRUE;
		}
		if (vmacSta_p->BFMRconfig.bw != BFMRconfigbw) {
			vmacSta_p->BFMRconfig.bw = BFMRconfigbw;
			vmacSta_p->bBFMRconfigChanged = TRUE;
		}

	} else {
		vmacSta_p->BFMRconfig.chan = channel;
		vmacSta_p->BFMRconfig.bw = BFMRconfigbw;
		vmacSta_p->BFMRinitstatus.bw_init = 1;
		vmacSta_p->BFMRinitstatus.chan_init = 1;
	}
}

#ifdef SOC_W906X
extern UINT32 GetCenterFreq(UINT32 ch, UINT32 bw);

int
wlFwSetChannel(struct net_device *netdev, u_int8_t channel, u_int8_t secchannel,
	       CHNL_FLAGS Chanflag, u_int8_t initRateTable)
#else
int
wlFwSetChannel(struct net_device *netdev, u_int8_t channel, CHNL_FLAGS Chanflag,
	       u_int8_t initRateTable)
#endif
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT8 ChnlWidth, ExtChnlOffset;
	HostCmd_FW_SET_RF_CHANNEL *pCmd =
		(HostCmd_FW_SET_RF_CHANNEL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
#ifdef SOC_W906X
	UINT32 centerfreq;
#endif

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "channel: %i", channel);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_RF_CHANNEL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RF_CHANNEL);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_RF_CHANNEL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->CurrentChannel = channel;
	pCmd->Action = ENDIAN_SWAP16(WL_SET);
	pCmd->ChannelFlags.FreqBand = Chanflag.FreqBand;
	pCmd->ChannelFlags.ChnlWidth = Chanflag.ChnlWidth;
#ifdef SOC_W906X
	pCmd->Channel2 = secchannel;
	pCmd->ChannelFlags.radiomode = Chanflag.radiomode;
	pCmd->ChannelFlags.FreqBand2 = Chanflag.FreqBand2;
	pCmd->ChannelFlags.ChnlWidth2 = Chanflag.ChnlWidth2;
	pCmd->ChannelFlags.isDfsChan = Chanflag.isDfsChan;
	pCmd->ChannelFlags.isDfsChan2 = Chanflag.isDfsChan2;
#endif
	if (Chanflag.ChnlWidth == CH_AUTO_WIDTH) {
		if (Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ) {
			pCmd->ChannelFlags.ChnlWidth = CH_40_MHz_WIDTH;
		} else {
			pCmd->ChannelFlags.ChnlWidth = CH_80_MHz_WIDTH;
		}
	}
	if (Chanflag.ExtChnlOffset == EXT_CH_ABOVE_CTRL_CH)
		pCmd->ChannelFlags.ActPrimary = ACT_PRIMARY_CHAN_0;
	else if (Chanflag.ExtChnlOffset == EXT_CH_BELOW_CTRL_CH)
		pCmd->ChannelFlags.ActPrimary = ACT_PRIMARY_CHAN_1;
	else
		pCmd->ChannelFlags.ActPrimary = ACT_PRIMARY_CHAN_0;

	if (pCmd->ChannelFlags.ChnlWidth == CH_80_MHz_WIDTH) {
		if (Chanflag.radiomode == RADIO_MODE_7x7p1x1)
			pCmd->ChannelFlags.ActPrimary =
				macMgmtMlme_Get80MHzPrimaryChannelOffset
				(secchannel);
		else
			pCmd->ChannelFlags.ActPrimary =
				macMgmtMlme_Get80MHzPrimaryChannelOffset
				(channel);
	}
#ifdef SOC_W906X
	if (pCmd->ChannelFlags.ChnlWidth == CH_160_MHz_WIDTH) {
		centerfreq = GetCenterFreq(channel, CH_80_MHz_WIDTH);
		pCmd->ChannelFlags.ActPrimary =
			macMgmtMlme_Get80MHzPrimaryChannelOffset(channel);
		pCmd->ChannelFlags.radiomode = RADIO_MODE_80p80;	/* force radio mode to RADIO_MODE_80p80 */
		pCmd->ChannelFlags.FreqBand2 = Chanflag.FreqBand;
		pCmd->ChannelFlags.ChnlWidth = CH_80_MHz_WIDTH;
		pCmd->ChannelFlags.ChnlWidth2 = CH_80_MHz_WIDTH;
	}
#else
	if (pCmd->ChannelFlags.ChnlWidth == CH_160_MHz_WIDTH)
		pCmd->ChannelFlags.ActPrimary =
			macMgmtMlme_Get160MHzPrimaryChannelOffset(channel);
#endif

	/*pCmd->initRateTable = initRateTable; *//*un-used field in current FW */

#ifdef MV_CPU_BE
	pCmd->ChannelFlags.u32_data =
		ENDIAN_SWAP32(pCmd->ChannelFlags.u32_data);
#endif

	ChnlWidth = pCmd->ChannelFlags.ChnlWidth;
	ExtChnlOffset = Chanflag.ExtChnlOffset;
	BFMRconfigChanBw(wlpptr, ChnlWidth, ExtChnlOffset, channel);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_RF_CHANNEL));
	SMAC_RX_DISABLE(wlpptr, mib, vmacSta_p->VMacEntry.macId);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RF_CHANNEL);
	SMAC_RX_ENABLE(wlpptr, mib, vmacSta_p->VMacEntry.macId);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	return retval;
}

#ifdef SOC_W906X
int
wlFwCreateBAStream(struct net_device *dev, u_int32_t BarThrs,
		   u_int32_t WindowSize, u_int8_t * Macaddr,
		   u_int8_t DialogToken, u_int8_t Tid, u_int32_t ba_type,
		   u_int32_t direction, u_int8_t ParamInfo,
		   u_int8_t * SrcMacaddr, UINT16 seqNo, UINT32 vhtrxfactor,
		   UINT32 queueid, u_int16_t staid)
#else
int
wlFwCreateBAStream(struct net_device *dev, u_int32_t BarThrs,
		   u_int32_t WindowSize, u_int8_t * Macaddr,
		   u_int8_t DialogToken, u_int8_t Tid, u_int32_t ba_type,
		   u_int32_t direction, u_int8_t ParamInfo,
		   u_int8_t * SrcMacaddr, UINT16 seqNo, UINT32 vhtrxfactor,
		   UINT32 queueid)
#endif
{

	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	HostCmd_FW_BASTREAM *pCmd =
		(HostCmd_FW_BASTREAM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef SOC_W906X
	int cnt = 0;
	UINT32 factor;
	UINT8 ampduDensity = (ParamInfo & 0x1c) >> 2;
	UINT32 ampduBytes =
		vhtrxfactor ? ((1 << ((vhtrxfactor & 0x7) + 13)) -
			       4) : ((1 << ((ParamInfo & 0x3) + 13)) - 4);

	WLDBG_INFO(DBG_LEVEL_14,
		   "before cap: ParamInfo %x, vhtrxfactor %x, WindowSize %x\n",
		   ParamInfo, vhtrxfactor, WindowSize);

	if (ampduDensity < wlpptr->vmacSta_p->ampduDensityCap) {
		WLDBG_INFO(DBG_LEVEL_14, "cap density from %i to %i\n",
			   ampduDensity, wlpptr->vmacSta_p->ampduDensityCap);
		ParamInfo &= 0xe3;
		ParamInfo |= (wlpptr->vmacSta_p->ampduDensityCap << 2);
	}
	if (ampduBytes > wlpptr->vmacSta_p->ampduBytesCap) {
		WLDBG_INFO(DBG_LEVEL_14, "cap max ampdu bytes from %i to %i\n",
			   ampduBytes, wlpptr->vmacSta_p->ampduBytesCap);
		factor = (wlpptr->vmacSta_p->ampduBytesCap + 4) / 8192;
		while (factor) {
			cnt++;
			factor >>= 1;
		}
		factor = cnt;
		if (vhtrxfactor) {
			vhtrxfactor &= 0xfffffff8;
			vhtrxfactor |= factor;
		} else {
			ParamInfo &= 0xfc;
			ParamInfo |= factor;
		}
	}
	if (WindowSize > wlpptr->vmacSta_p->ampduWindowSizeCap) {
		WLDBG_INFO(DBG_LEVEL_14, "cap window size from %i to %i\n",
			   WindowSize, wlpptr->vmacSta_p->ampduWindowSizeCap);
		WindowSize = wlpptr->vmacSta_p->ampduWindowSizeCap;
	}
	WLDBG_INFO(DBG_LEVEL_14,
		   "after cap: ParamInfo %x, vhtrxfactor %x, WindowSize %x\n",
		   ParamInfo, vhtrxfactor, WindowSize);
#endif /* #ifdef SOC_W906X */
	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Create BA Stream: %i");
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BASTREAM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->CmdHdr.Result = ENDIAN_SWAP16(0xffff);
#ifdef SOC_W906X
	pCmd->ActionType = ENDIAN_SWAP16(BaCreateStream);
	pCmd->staid = ENDIAN_SWAP16(staid);
#else
	pCmd->ActionType = ENDIAN_SWAP32(BaCreateStream);
#endif
	pCmd->BaInfo.CreateParams.BarThrs = ENDIAN_SWAP32(BarThrs);
	pCmd->BaInfo.CreateParams.WindowSize = ENDIAN_SWAP32(WindowSize);
	pCmd->BaInfo.CreateParams.IdleThrs = ENDIAN_SWAP32(0x22000);
	memcpy(&pCmd->BaInfo.CreateParams.PeerMacAddr[0], Macaddr, 6);
	pCmd->BaInfo.CreateParams.DialogToken = DialogToken;
	pCmd->BaInfo.CreateParams.Tid = Tid;
	pCmd->BaInfo.CreateParams.Flags.BaType = ba_type;
	pCmd->BaInfo.CreateParams.Flags.BaDirection = direction;
	pCmd->BaInfo.CreateParams.QueueId = queueid;
	pCmd->BaInfo.CreateParams.ParamInfo = ParamInfo;
	pCmd->BaInfo.CreateParams.ResetSeqNo = 0;
	pCmd->BaInfo.CreateParams.CurrentSeq = ENDIAN_SWAP16(seqNo);
	pCmd->BaInfo.CreateParams.vhtrxfactor = ENDIAN_SWAP32(vhtrxfactor);
#ifdef V6FW
	/* SrcMacaddr is used for client mode, not required for AP mode. */
	if (SrcMacaddr)
		memcpy(&pCmd->BaInfo.CreateParams.StaSrcMacAddr[0], SrcMacaddr,
		       6);
	else
		memset(&pCmd->BaInfo.CreateParams.StaSrcMacAddr[0], 0x00, 6);
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_BASTREAM));
	retval = wlexecuteCommand(dev, HostCmd_CMD_BASTREAM);
	//      printk("Value of result = %x\n",pCmd->CmdHdr.Result);
	if (pCmd->CmdHdr.Result != 0) {
		//              printk("FW not ready to do addba!!!!!!!!! \n");
		retval = FAIL;
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwCheckBAStream(struct net_device *dev, u_int32_t BarThrs,
		  u_int32_t WindowSize, u_int8_t * Macaddr,
		  u_int8_t DialogToken, u_int8_t Tid, u_int32_t ba_type,
		  int32_t qid, u_int8_t ParamInfo)
{

	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	HostCmd_FW_BASTREAM *pCmd =
		(HostCmd_FW_BASTREAM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Create BA Stream: %i");
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BASTREAM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->CmdHdr.Result = ENDIAN_SWAP16(0xffff);
#ifdef SOC_W906X
	pCmd->ActionType = ENDIAN_SWAP16(BaCheckCreateStream);
#else
	pCmd->ActionType = ENDIAN_SWAP32(BaCheckCreateStream);
#endif
	pCmd->BaInfo.CreateParams.BarThrs = ENDIAN_SWAP32(63);	//BarThrs;
	pCmd->BaInfo.CreateParams.WindowSize = ENDIAN_SWAP32(64);	/*WindowSize; */
	pCmd->BaInfo.CreateParams.IdleThrs = ENDIAN_SWAP32(0x22000);
	memcpy(&pCmd->BaInfo.CreateParams.PeerMacAddr[0], Macaddr, 6);
	pCmd->BaInfo.CreateParams.DialogToken = DialogToken;
	pCmd->BaInfo.CreateParams.Tid = Tid;
	pCmd->BaInfo.CreateParams.Flags.BaType = ba_type;
	pCmd->BaInfo.CreateParams.Flags.BaDirection = 0;
	pCmd->BaInfo.CreateParams.QueueId = qid;
	pCmd->BaInfo.CreateParams.ParamInfo = ParamInfo;
	pCmd->BaInfo.CreateParams.ResetSeqNo = 1;
	pCmd->BaInfo.CreateParams.CurrentSeq = ENDIAN_SWAP16(0);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_BASTREAM));
	retval = wlexecuteCommand(dev, HostCmd_CMD_BASTREAM);
	//      printk("Value of result = %x\n",pCmd->CmdHdr.Result);
	if (pCmd->CmdHdr.Result != 0) {
		//printk("FW not ready to do addba!!!!!!!!! \n");
		retval = FAIL;
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;

}

int
wlFwGetSeqNoBAStream(struct net_device *dev, u_int8_t * Macaddr,
		     uint8_t Tid, uint16_t * pbaseq_no)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	HostCmd_GET_SEQNO *pCmd = (HostCmd_GET_SEQNO *) & wlpptr->pCmdBuf[0];
	int retval;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Get BA Stream Seqno %i");
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

	memset(pCmd, 0x00, sizeof(HostCmd_GET_SEQNO));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_SEQNO);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_GET_SEQNO));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	memcpy(pCmd->MacAddr, Macaddr, 6);
	pCmd->TID = Tid;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_GET_SEQNO));

	retval = wlexecuteCommand(dev, HostCmd_CMD_GET_SEQNO);
	if (retval == 0) {
		*pbaseq_no = ENDIAN_SWAP16(pCmd->SeqNo);
	}

	if (wfa_11ax_pf)
		*pbaseq_no += 2;

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwUpdateDestroyBAStream(struct net_device *dev, u_int32_t ba_type,
			  u_int32_t direction, u_int8_t stream, u_int8_t tid,
			  u_int8_t * Macaddr, u_int16_t staid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	HostCmd_FW_BASTREAM *pCmd =
		(HostCmd_FW_BASTREAM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Destroy BA Stream: %i");
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BASTREAM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#ifdef SOC_W906X
	pCmd->ActionType = ENDIAN_SWAP16(BaDestroyStream);
	pCmd->staid = ENDIAN_SWAP16(staid);
#else
	pCmd->ActionType = ENDIAN_SWAP32(BaDestroyStream);
#endif
	pCmd->BaInfo.DestroyParams.Flags.BaType = ba_type;
	pCmd->BaInfo.DestroyParams.Flags.BaDirection = direction;
	pCmd->BaInfo.DestroyParams.FwBaContext.Context = ENDIAN_SWAP32(stream);
	pCmd->BaInfo.DestroyParams.Tid = tid;
	memcpy(&pCmd->BaInfo.DestroyParams.PeerMacAddr[0], Macaddr, 6);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_BASTREAM));
	retval = wlexecuteCommand(dev, HostCmd_CMD_BASTREAM);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;

}

int
wlFwUpdateUpdateBAStream(struct net_device *dev, u_int32_t ba_type,
			 u_int32_t direction, u_int16_t seqNum)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	HostCmd_FW_BASTREAM *pCmd =
		(HostCmd_FW_BASTREAM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Update BA Stream: %i");
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BASTREAM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#ifdef SOC_W906X
	pCmd->ActionType = ENDIAN_SWAP16(BaUpdateStream);
#else
	pCmd->ActionType = ENDIAN_SWAP32(BaUpdateStream);
#endif
	pCmd->BaInfo.UpdtSeqNum.Flags.BaType = ba_type;
	pCmd->BaInfo.UpdtSeqNum.Flags.BaDirection = direction;
	pCmd->BaInfo.UpdtSeqNum.BaSeqNum = ENDIAN_SWAP16(seqNum);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_BASTREAM));
	retval = wlexecuteCommand(dev, HostCmd_CMD_BASTREAM);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;

}

int
wlFwFlushBAStream(struct net_device *dev, u_int32_t ba_type,
		  u_int32_t direction)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	HostCmd_FW_BASTREAM *pCmd =
		(HostCmd_FW_BASTREAM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Flush BA Stream: %i");
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BASTREAM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_BASTREAM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#ifdef SOC_W906X
	pCmd->ActionType = ENDIAN_SWAP16(BaFlushStream);
#else
	pCmd->ActionType = ENDIAN_SWAP32(BaFlushStream);
#endif
	pCmd->BaInfo.FlushParams.Flags.BaType = ba_type;
	pCmd->BaInfo.FlushParams.Flags.BaDirection = direction;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_FW_BASTREAM));
	retval = wlexecuteCommand(dev, HostCmd_CMD_BASTREAM);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;

}

int
wlFwSetNewStn(struct net_device *dev, u_int8_t * staaddr, u_int16_t assocId,
	      u_int16_t stnId, u_int16_t action, PeerInfo_t * pPeerInfo,
	      UINT8 Qosinfo, UINT8 isQosSta, UINT8 wds)
{
#ifndef SOC_W906X
	extern BOOLEAN force_5G_channel;
#endif
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	extStaDb_StaInfo_t *pStaInfo;
	HostCmd_FW_SET_NEW_STN *pCmd =
		(HostCmd_FW_SET_NEW_STN *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef UAPSD_SUPPORT
	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "staid: %s, association ID: %i stnId: %i action %i qosinfo %i qosSta %i\n",
			 mac_display(staaddr), assocId, stnId, action, Qosinfo,
			 isQosSta);
#else
	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "bssid: %s, association ID: %i stnId: %i action %i",
			 mac_display(bssId), assocId, stnId, action);
#endif

#ifndef SOC_W906X
	if (force_5G_channel) {
		PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
	} else {
#endif
		if (PhyDSSSTable->CurrChan <= 14)
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
		else
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
#ifndef SOC_W906X
	}
#endif

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_NEW_STN));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_NEW_STN);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_NEW_STN));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->AID = ENDIAN_SWAP16(assocId);
	pCmd->StnId = ENDIAN_SWAP16(stnId);
	pCmd->Action = ENDIAN_SWAP16(action);

#ifdef SOC_W906X
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
		pCmd->StaMode = 1;
	else
		pCmd->StaMode = 0;
#endif

	if (pPeerInfo) {
		if (wlpptr->retrycfgenable) {
			pPeerInfo->retrycntQoS.retrycfgenable = 1;
			if (PhyDSSSTable->Chanflag.FreqBand ==
			    FREQ_BAND_2DOT4GHZ || !pPeerInfo->HTRateBitMap) {
				printk("legacy:retry cfg \n");
				pPeerInfo->retrycntQoS.retrycntBK =
					wlpptr->retrycfgVAP.RetryLegacy[0];
				pPeerInfo->retrycntQoS.retrycntBE =
					wlpptr->retrycfgVAP.RetryLegacy[1];
				pPeerInfo->retrycntQoS.retrycntVI =
					wlpptr->retrycfgVAP.RetryLegacy[2];
				pPeerInfo->retrycntQoS.retrycntVO =
					wlpptr->retrycfgVAP.RetryLegacy[3];

			} else if (!pPeerInfo->vht_cap) {
				printk("11n:retry cfg \n");
				pPeerInfo->retrycntQoS.retrycntBK =
					wlpptr->retrycfgVAP.Retry11n[0];
				pPeerInfo->retrycntQoS.retrycntBE =
					wlpptr->retrycfgVAP.Retry11n[1];
				pPeerInfo->retrycntQoS.retrycntVI =
					wlpptr->retrycfgVAP.Retry11n[2];
				pPeerInfo->retrycntQoS.retrycntVO =
					wlpptr->retrycfgVAP.Retry11n[3];
			} else if (pPeerInfo->vht_cap) {
				printk("11ac: retry cfg \n");
				pPeerInfo->retrycntQoS.retrycntBK =
					wlpptr->retrycfgVAP.Retry11ac[0];
				pPeerInfo->retrycntQoS.retrycntBE =
					wlpptr->retrycfgVAP.Retry11ac[1];
				pPeerInfo->retrycntQoS.retrycntVI =
					wlpptr->retrycfgVAP.Retry11ac[2];
				pPeerInfo->retrycntQoS.retrycntVO =
					wlpptr->retrycfgVAP.Retry11ac[3];
			}
			printk(" BK %d BE %d VI %d VO %d \n",
			       pPeerInfo->retrycntQoS.retrycntBK,
			       pPeerInfo->retrycntQoS.retrycntBE,
			       pPeerInfo->retrycntQoS.retrycntVI,
			       pPeerInfo->retrycntQoS.retrycntVO);
		} else {
			pPeerInfo->retrycntQoS.retrycfgenable = 0;
		}
		pPeerInfo->TxBFCapabilities =
			WORD_SWAP(pPeerInfo->TxBFCapabilities);
		memcpy((void *)&(pCmd->PeerInfo), (void *)pPeerInfo,
		       sizeof(PeerInfo_t));
		if (wlpptr->wlpd_p->ldpcdisable) {
			pCmd->PeerInfo.HTCapabilitiesInfo.AdvCoding = 0;
			((IEEEtypes_VHT_Cap_Info_t *) & pCmd->PeerInfo.
			 vht_cap)->RxLDPC = 0;
		}

		if (((pStaInfo =
		      extStaDb_GetStaInfo(vmacSta_p,
					  (IEEEtypes_MacAddr_t *) staaddr,
					  STADB_DONT_UPDATE_AGINGTIME)) != NULL)
		    && (action == StaInfoDbActionAddEntry)) {
#ifdef STA_FULL_HTVHT_CAP
			memcpy((void *)&(pCmd->HtElem),
			       (void *)&(pStaInfo->HtElem),
			       sizeof(IEEEtypes_HT_Element_t));
			memcpy((void *)&(pCmd->vhtCap),
			       (void *)&(pStaInfo->vhtCap),
			       sizeof(IEEEtypes_VhtCap_t));
			if (wlpptr->wlpd_p->ldpcdisable) {
				pCmd->HtElem.HTCapabilitiesInfo.AdvCoding = 0;
				pCmd->vhtCap.cap.RxLDPC = 0;
			}
#endif
#if defined(SOC_W906X) && defined(CONFIG_IEEE80211W)
			pCmd->mfpEnabled = pStaInfo->Ieee80211wSta;
#endif
		}
	}
	memcpy(&pCmd->MacAddr[0], staaddr, 6);
#ifdef UAPSD_SUPPORT
	pCmd->Qosinfo = Qosinfo;
	pCmd->isQosSta = isQosSta;
#endif
#ifdef MULTI_AP_SUPPORT
	if ((pStaInfo =
	     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) staaddr,
				 STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
		printk("wlFwSetNewStn pStaInfo->MultiAP_4addr = %d\n",
		       pStaInfo->MultiAP_4addr);
		if (pStaInfo->MultiAP_4addr &&
		    ((mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS) ||
		     (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA))) {
			wds = 4;
		}
	}

	if (wds == 4) {
		printk("wlFwSetNewStn multi_ap_attr = %d, wds = %d\n",
		       mib->multi_ap_attr, wds);
	}
#endif /* MULTI_AP_SUPPORT */

	pCmd->Wds = wds;
#ifdef SOC_W906X
	pCmd->maxAmsduSubframes = *mib->mib_amsdu_pktcnt;
#endif
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_NEW_STN));
	retval = wlexecuteCommand(dev, HostCmd_CMD_SET_NEW_STN);
	retval = ENDIAN_SWAP32((int)(pCmd->FwStaPtr));
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	// WAR for 4.40.2, 4.49.1_24G:
	// AP won't stop sending tf that some STA (eg: Cypress one) may fail to assoc / ping
	// => Stop tf if STA leaves (# of connected_ap < sta_cnt of tf)
	if (wfa_11ax_pf) {
		static UINT32 last_stacnt;
		UINT32 entries = extStaDb_entries(vmacSta_p, 0);
		tf_test_arg_t *ptf_arg = &wlpptr->tf_test_arg;

		printk("==>[wfa_11ax_pf], %s(), assoc_sta_cnt: %u\n", __func__,
		       entries);
		if (ptf_arg->tf.common.tf_num_users > 0) {
			/*
			   // Skip resuming the tf
			   if ((entries > last_stacnt) && (entries == ptf_arg->tf.common.tf_num_users)) {
			   // If assoc_sta increasing & reach the number of users in .conf => resume the tf
			   printk("==>[wfa_11ax_pf], resume tf, (type=%u, rate_info=0x%x, period=%u, pad=%u\n",
			   ptf_arg->type, ptf_arg->rate_info, ptf_arg->period, ptf_arg->pad_num
			   );
			   wlFwSentTriggerFrameCmd(dev, 3, ptf_arg->type, ptf_arg->rate_info,
			   ptf_arg->period, ptf_arg->pad_num, (void *)(&ptf_arg->tf));
			   } */
			if ((entries < last_stacnt) &&
			    (entries < ptf_arg->tf.common.tf_num_users)) {
				// If a STA is leaving && < num_user of tf => stop the tf
				printk("==>[wfa_11ax_pf], stopping tf\n");
				wlFwSentTriggerFrameCmd(dev, 0, ptf_arg->type,
							ptf_arg->rate_info,
							ptf_arg->period,
							ptf_arg->pad_num,
							(void *)(&ptf_arg->tf));
				printk("==>[wfa_11ax_pf], tf stopped! \n");
			}
		}
		last_stacnt = entries;
	}
	return retval;
}

int
wlFwSetKeepAliveTick(struct net_device *dev, u_int8_t tick)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	//      static int i;
	HostCmd_FW_SET_KEEP_ALIVE_TICK *pCmd =
		(HostCmd_FW_SET_KEEP_ALIVE_TICK *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	//      WLDBG_ENTER_INFO(DBG_LEVEL_0,"FW keepalive %i",i );
#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_CMD_SET_KEEP_ALIVE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_KEEP_ALIVE);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_KEEP_ALIVE_TICK));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->tick = tick;

	//      WLDBG_DUMP_DATA(DBG_LEVEL_0,(void *) pCmd,sizeof(HostCmd_FW_SET_KEEP_ALIVE_TICK));
	retval = wlexecuteCommand(dev, HostCmd_CMD_SET_KEEP_ALIVE);
	if (retval == TIMEOUT) {
		if (wlpptr->netDevStats.tx_heartbeat_errors++ % 2)
			wlResetTask(dev);
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwGetWatchdogbitmap(struct net_device *dev, u_int8_t * bitmap)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

	HostCmd_FW_GET_WATCHDOG_BITMAP *pCmd =
		(HostCmd_FW_GET_WATCHDOG_BITMAP *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	//      WLDBG_ENTER_INFO(DBG_LEVEL_1,"FW keepalive %i",i );
#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_CMD_GET_WATCHDOG_BITMAP));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_WATCHDOG_BITMAP);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_WATCHDOG_BITMAP));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	//      WLDBG_DUMP_DATA(DBG_LEVEL_1,(void *) pCmd,sizeof(HostCmd_FW_SET_KEEP_ALIVE_TICK));
	retval = wlexecuteCommand(dev, HostCmd_CMD_GET_WATCHDOG_BITMAP);
	if (retval == SUCCESS) {
		*bitmap = pCmd->Watchdogbitmap;
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetApMode(struct net_device *netdev, u_int8_t ApMode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_APMODE *pCmd =
		(HostCmd_FW_SET_APMODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "AP Mode = %d", ApMode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_CMD_SET_APMODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_APMODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_APMODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->ApMode = ApMode;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_APMODE));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_APMODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetAPBss(struct net_device *netdev, wlfacilitate_e facility)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	HostCmd_BSS_START *pCmd = (HostCmd_BSS_START *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "AP bss %s",
			 (facility == WL_ENABLE) ? "enable" : "disable");
	if (facility == WL_ENABLE) {
		wlpptr->wlpd_p->bBssStartEnable = 1;
		wlpptr->wlpd_p->bStopBcnProbeResp = FALSE;
	} else {
		wlpptr->wlpd_p->bBssStartEnable = 0;
	}

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_BSS_START));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BSS_START);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_BSS_START));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Enable = ENDIAN_SWAP32(facility);
	pCmd->CmdHdr.macid = vmacSta_p->VMacEntry.macId;
	pCmd->Amsdu = *(mib->mib_amsdutx);
#ifdef SOC_W906X
	pCmd->IntfFlag = INTF_AP_MODE;
	pCmd->qosEnabled = *(mib->QoSOptImpl);
	pCmd->nonQosMcBcFlag = *(mib->disable_qosctl);
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_BSS_START));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_BSS_START);
#ifdef SOC_W906X
	if (pCmd->Status)
		printk("wlFwSetAPBss::: bss %s failed with reason code %d  facility=0x%08x \n", (facility == WL_ENABLE) ? "start" : "stop", pCmd->Status, facility);
	else {
		if (facility == WL_ENABLE)
			SMAC_RX_ENABLE(wlpptr, mib, vmacSta_p->VMacEntry.macId);
		else
			SMAC_RX_DISABLE(wlpptr, mib,
					vmacSta_p->VMacEntry.macId);
	}
#endif
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetAPUpdateTim(struct net_device *netdev, u_int16_t assocId, Bool_e set)
{
#ifndef SOC_W906X
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_UpdateTIM *pCmd = (HostCmd_UpdateTIM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "association ID: %i %s", assocId,
			 (set == WL_TRUE) ? "update" : "noact");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_UpdateTIM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_UPDATE_TIM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_UpdateTIM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->UpdateTIM.Aid = ENDIAN_SWAP16(assocId);
	pCmd->UpdateTIM.Set = ENDIAN_SWAP32(set);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_UpdateTIM));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_UPDATE_TIM);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
#else
	return SUCCESS;
#endif
}

#ifndef SOC_W906X
int
wlFwSetAPBcastSSID(struct net_device *netdev, wlfacilitate_e facility)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SSID_BROADCAST *pCmd =
		(HostCmd_SSID_BROADCAST *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0,
			 "AP SSID broadcast %s",
			 (facility == WL_ENABLE) ? "enable" : "disable");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SSID_BROADCAST));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BROADCAST_SSID_ENABLE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SSID_BROADCAST));
	pCmd->SsidBroadcastEnable = ENDIAN_SWAP32(facility);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SSID_BROADCAST));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_BROADCAST_SSID_ENABLE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetWmm(struct net_device *netdev, wlfacilitate_e facility)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SetWMMMode *pCmd =
		(HostCmd_FW_SetWMMMode *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SetWMMMode));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_WMM_MODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SetWMMMode));
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Action = ENDIAN_SWAP16(facility);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_WMM_MODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif /* #ifndef SOC_W906X */

int
wlFwSetGProt(struct net_device *netdev, wlfacilitate_e facility)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_G_PROTECT_FLAG *pCmd =
		(HostCmd_FW_SET_G_PROTECT_FLAG *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "G prot mode %d", facility);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_G_PROTECT_FLAG));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_G_PROTECT_FLAG);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_G_PROTECT_FLAG));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->GProtectFlag = ENDIAN_SWAP32(facility);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_G_PROTECT_FLAG));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_G_PROTECT_FLAG);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetEdcaParam(struct net_device *netdev, u_int8_t Indx, u_int32_t CWmin,
		 u_int32_t CWmax, u_int8_t AIFSN, u_int16_t TXOPLimit)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_EDCA_PARAMS *pCmd =
		(HostCmd_FW_SET_EDCA_PARAMS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, " wlFwSetEdcaParam ");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_EDCA_PARAMS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_EDCA_PARAMS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_EDCA_PARAMS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Action = ENDIAN_SWAP16(0xffff);	//set everything
	pCmd->TxOP = ENDIAN_SWAP16(TXOPLimit);
	pCmd->CWMax = ENDIAN_SWAP32(CWmax);
	pCmd->CWMin = ENDIAN_SWAP32(CWmin);
	pCmd->AIFSN = AIFSN;
	pCmd->TxQNum = Indx;

#ifdef SOC_W906X
	/* The array index defined in qos.h has a reversed bk and be.
	   The HW queue was not used this way; the qos code needs to be changed or
	   checked */
	if (Indx == 0)
		pCmd->TxQNum = 1;
	else if (Indx == 1)
		pCmd->TxQNum = 0;
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_EDCA_PARAMS));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_EDCA_PARAMS);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwAcMaxTolerableDelay(struct net_device *netdev, u_int8_t action, u_int8_t ac,
			u_int32_t * maxdelay)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_MAX_DELAY_BY_AC *pCmd =
		(HostCmd_FW_SET_MAX_DELAY_BY_AC *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, " wlFwAcMaxTolerableDelay ");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_MAX_DELAY_BY_AC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MAX_DELAY_BY_AC);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_MAX_DELAY_BY_AC));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->action = action;
	pCmd->ac = ac;
	if (action == 0)
		pCmd->maxTolerableDelay = *maxdelay;

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_MAX_DELAY_BY_AC);
	if (!retval && (action == 1)) {
		printk(" ac %x max tolerable delay %x\n", pCmd->ac,
		       pCmd->maxTolerableDelay);
		*maxdelay = pCmd->maxTolerableDelay;
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

void
BFMRconfigVHT_HT(struct wlprivate *wlpptr, UINT8 * IeListHT, UINT8 * IeListVHT)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->BFMRinitDone) {
		if (IeListHT &&
		    memcmp(vmacSta_p->BFMRconfig.ht_cap, IeListHT, 28)) {
			memcpy(vmacSta_p->BFMRconfig.ht_cap, IeListHT, 28);
			vmacSta_p->bBFMRconfigChanged = TRUE;
		}
		if (IeListVHT &&
		    memcmp(vmacSta_p->BFMRconfig.vht_cap_data, IeListVHT + 2,
			   12)) {
			memcpy(vmacSta_p->BFMRconfig.vht_cap_data,
			       IeListVHT + 2, 12);
			vmacSta_p->bBFMRconfigChanged = TRUE;
		}

	} else {
		if (IeListHT)
			memcpy(vmacSta_p->BFMRconfig.ht_cap, IeListHT, 28);
		if (IeListVHT)
			memcpy(vmacSta_p->BFMRconfig.vht_cap_data,
			       IeListVHT + 2, 12);
		vmacSta_p->BFMRinitstatus.ht_cap_init = 1;
		vmacSta_p->BFMRinitstatus.vht_cap_init = 1;
	}

}

int
wlFwSetIEs(struct net_device *netdev)
{
#ifdef SOC_W906X
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib_s = vmacSta_p->ShadowMib802dot11,
		*mib = vmacSta_p->ShadowMib802dot11;
	HostCmd_FW_SetIEs *setFwIes =
		(HostCmd_FW_SetIEs *) & wlpptr->pCmdBuf[0];
	UINT8 *tail = (UINT8 *) setFwIes->beacon_buf;
	UINT8 *ht_cap = NULL, *vht_cap = NULL;
	UINT16 ie_len;
	int retval = FAIL;
	unsigned long flags;
	UINT32 mbssidGID;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(setFwIes, 0x00, sizeof(HostCmd_FW_SetIEs));
	setFwIes->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_IES);
	setFwIes->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	setFwIes->Action = ENDIAN_SWAP16(HostCmd_ACT_GEN_SET);
	setFwIes->CmdHdr.macid = vmacSta_p->VMacEntry.macId;

	/***************************************************************************************************/
	/*IMPORTANT: When adding new IE or IE's fields, make sure Hostcmd and Generic_Beacon buffer in fw has enough size */
	/***************************************************************************************************/

	for (mbssidGID = 0; mbssidGID < MAX_MBSSID_SET; mbssidGID++) {
		mbss_set_t *pset = &wlpptr->wlpd_p->mbssSet[mbssidGID];
		//this bssid already be grouped in a set
		if (pset->mbssid_set & (1 << vmacSta_p->VMacEntry.macId)) {
			//printk("%s: %u %x %u=%u\n",__func__, *(mib->mib_mbssid), *(mib->mib_ApMode), vmacSta_p->VMacEntry.macId, wlpptr->wlpd_p->mbssSet[mbssidGID].primbss );
			break;
		}
	}

	if ((*(mib->mib_mbssid) == 1) && (mbssidGID < MAX_MBSSID_SET) && (*(mib->mib_ApMode) & AP_MODE_11AX) && (vmacSta_p->VMacEntry.macId == wlpptr->wlpd_p->mbssSet[mbssidGID].primbss)) {	//primary bssid

		mbss_set_t *pset = &wlpptr->wlpd_p->mbssSet[mbssidGID];
		u32 bitmap = pset->mbssid_set;
		u32 idx = 0;
		struct wlprivate *wlp =
			NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

		while (bitmap) {

			if (bitmap & 0x1) {
				if (idx !=
				    wlpptr->wlpd_p->mbssSet[mbssidGID].
				    primbss) {
					struct wlprivate *wlp_ntxp =
						NETDEV_PRIV_P(struct wlprivate,
							      wlp->vdev[idx]);
					vmacApInfo_t *vmacSta_ntxp =
						wlp_ntxp->vmacSta_p;

					//vmacSta_ntxp = wlp_ntxp->vmacSta_p;
					ie_len = Add_Mbssid_IE(vmacSta_ntxp,
							       (IEEEtypes_Mbssid_Element_t
								*) tail);
					tail += ie_len;
					//printk("ie_len:%u\n",ie_len);
				}
			}

			idx++;
			bitmap >>= 1;
		}
	}

	if (*(mib_s->QoSOptImpl)) {
		u8 addedExtcap = FALSE;

		ht_cap = tail;
		if (vmacSta_p->wtp_info.WTP_enabled &&
		    vmacSta_p->wtp_info.extHtIE == true) {
			memcpy(tail, vmacSta_p->wtp_info.HTCapIE,
			       vmacSta_p->wtp_info.HTCapIE[1] + 2);
			tail += vmacSta_p->wtp_info.HTCapIE[1] + 2;
			memcpy(tail, vmacSta_p->wtp_info.addHTIE,
			       vmacSta_p->wtp_info.addHTIE[1] + 2);
			tail += (vmacSta_p->wtp_info.addHTIE[1] + 2);
		} else {
			ie_len = AddHT_IE(wlpptr->vmacSta_p,
					  (IEEEtypes_HT_Element_t *) tail);
			tail += ie_len;
			ie_len = AddAddHT_IE(wlpptr->vmacSta_p,
					     (IEEEtypes_Add_HT_Element_t *)
					     tail);
			tail += ie_len;
		}

		ie_len = AddChanReport_IE(wlpptr->vmacSta_p,
					  (IEEEtypes_ChannelReportEL_t *) tail);
		tail += ie_len;

#ifdef COEXIST_20_40_SUPPORT
		if (*(mib_s->mib_HT40MIntoler) &&
		    !((*(mib_s->mib_ApMode) & AP_MODE_BAND_MASK) >=
		      AP_MODE_A_ONLY ||
		      (*(mib_s->mib_ApMode) & AP_MODE_BAND_MASK) <=
		      AP_MODE_MIXED)) {
			ie_len = AddOverlap_BSS_Scan_Parameters_IE(wlpptr->
								   vmacSta_p,
								   (IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
								    *) tail);
			tail += ie_len;
			ie_len = AddExtended_Cap_IE(wlpptr->vmacSta_p,
						    (IEEEtypes_Extended_Cap_Element_t
						     *) tail);
			tail += ie_len;
			addedExtcap = TRUE;
		}
#endif
		/*Always add Extended Cap if in 5Ghz and VHT mode to pass wifi operating mode IE199 test */
		if (!addedExtcap &&
		    (*(mib->mib_ApMode) >= AP_MODE_5GHZ_11AC_ONLY)) {
			ie_len = AddExtended_Cap_IE(wlpptr->vmacSta_p,
						    (IEEEtypes_Extended_Cap_Element_t
						     *) tail);
			tail += ie_len;
		}

		/*Add 11ac VHT supported IEs */
		if (*(mib_s->mib_ApMode) & AP_MODE_11AC) {
			vht_cap = tail;
			if (vmacSta_p->wtp_info.WTP_enabled &&
			    vmacSta_p->wtp_info.extVhtIE == true) {
				memcpy(tail, vmacSta_p->wtp_info.vhtCapIE,
				       vmacSta_p->wtp_info.vhtCapIE[1] + 2);
				tail += (vmacSta_p->wtp_info.vhtCapIE[1] + 2);
				memcpy(tail, vmacSta_p->wtp_info.vhtInfoIE,
				       vmacSta_p->wtp_info.vhtInfoIE[1] + 2);
				tail += (vmacSta_p->wtp_info.vhtInfoIE[1] + 2);
			} else {
				ie_len = Build_IE_191(wlpptr->vmacSta_p, tail,
						      FALSE, 0);
				tail += ie_len;
				ie_len = Build_IE_192(wlpptr->vmacSta_p, tail);
				tail += ie_len;
			}
		}

		/*Add 11ax HE supported IEs */
		if (*(mib->mib_ApMode) & AP_MODE_11AX) {
			if (vmacSta_p->wtp_info.WTP_enabled &&
			    vmacSta_p->wtp_info.extHeIE == true) {
				memcpy(tail, vmacSta_p->wtp_info.heCapIe,
				       vmacSta_p->wtp_info.heCapIe[1] + 2);
				tail += (vmacSta_p->wtp_info.heCapIe[1] + 2);
				memcpy(tail, vmacSta_p->wtp_info.heOpIe,
				       vmacSta_p->wtp_info.heOpIe[1] + 2);
				tail += (vmacSta_p->wtp_info.heOpIe[1] + 2);
			} else {
				ie_len = Build_IE_HE_CAP(wlpptr->vmacSta_p,
							 tail);
				tail += ie_len;
				ie_len = Build_IE_HE_OP(wlpptr->vmacSta_p, tail,
							1);
				tail += ie_len;
			}

			if (vmacSta_p->VMacEntry.muedcaEnable) {
				ie_len = Build_IE_MU_EDCA(vmacSta_p, tail);
				tail += ie_len;
			}
			ie_len = Build_IE_SRP(wlpptr->vmacSta_p, tail);
			tail += ie_len;
		}

		if (ht_cap != NULL && vht_cap != NULL)
			BFMRconfigVHT_HT(wlpptr, ht_cap, vht_cap);

		if (*(mib->QoSOptImpl) && wfa_11ax_pf) {
			InitWMEParamElem(vmacSta_p);
			ie_len = AddWMEParam_IE((WME_param_elem_t *) tail);
			tail += ie_len;
		}

	}
	//add M IE
	ie_len = AddM_IE(wlpptr->vmacSta_p, (IEEEtypes_HT_Element_t *) tail);
	tail += ie_len;

	//add M Rptr IE
	if (*(mib_s->mib_RptrMode)) {
		ie_len = AddM_Rptr_IE(wlpptr->vmacSta_p,
				      (IEEEtypes_HT_Element_t *) tail);
		tail += ie_len;
	}
#ifdef MULTI_AP_SUPPORT
	if (mib->multi_ap_attr) {
		//add Multi-AP IE
		ie_len = Add_MultiAP_IE(wlpptr->vmacSta_p,
					(IEEEtypes_InfoElementHdr_t *) tail,
					WL_WLAN_TYPE_AP);
		tail += ie_len;
	}
#endif /*MULTI_AP_SUPPORT */

	if (vmacSta_p->wtp_info.WTP_enabled &&
	    vmacSta_p->wtp_info.extPropIE == true) {
		memcpy(tail, vmacSta_p->wtp_info.propIE,
		       vmacSta_p->wtp_info.propIE[1] + 2);
		tail += (vmacSta_p->wtp_info.propIE[1] + 2);
	}
#ifdef IEEE80211K
	ie_len = AddRRM_Cap_IE(wlpptr->vmacSta_p,
			       (IEEEtypes_RM_Enable_Capabilities_Element_t *)
			       tail);
	tail += ie_len;
#endif /* IEEE80211K */

#ifdef MRVL_80211R
	if (mib_s->RSNConfigWPA2->WPA2Enabled ||
	    mib_s->RSNConfigWPA2->WPA2OnlyEnabled) {
		if (vmacSta_p->MDIE[1] != 0) {
			memcpy(tail, vmacSta_p->MDIE, 5);
			tail += 5;
		}
	}
#endif

	setFwIes->CmdHdr.Length = (tail - setFwIes->beacon_buf)
		+ sizeof(FWCmdHdr)
		+ sizeof(UINT16);	//Action

#if defined(MRVL_WSC) || defined(MBO_SUPPORT)
	/* Add WSC IE or MBO IE in probe response */
	if ((vmacSta_p->WPSOn || vmacSta_p->Mib802dot11->mib_mbo_enabled) &&
	    (tail - setFwIes->beacon_buf + vmacSta_p->thisprobeRespIEs.Len) <=
	    MAX_BEACON_SIZE) {
		memcpy(tail, &vmacSta_p->thisprobeRespIEs.WSCData[0],
		       vmacSta_p->thisprobeRespIEs.Len);
		tail += vmacSta_p->thisprobeRespIEs.Len;
	}
#endif
	macMgmtMlme_UpdateProbeRspExtraIes(vmacSta_p, setFwIes->beacon_buf,
					   tail - setFwIes->beacon_buf);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)setFwIes, setFwIes->CmdHdr.Length);

	setFwIes->CmdHdr.Length = ENDIAN_SWAP16(setFwIes->CmdHdr.Length);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_IES);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
#else
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	HostCmd_FW_SetIEs *pCmd = (HostCmd_FW_SetIEs *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	int retvalVHT = 0, retvalProprietary = 0;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SetIEs));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_IES);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SetIEs));
	pCmd->Action = ENDIAN_SWAP16(HostCmd_ACT_GEN_SET);
	pCmd->CmdHdr.macid = vmacSta_p->VMacEntry.macId;
	retval = 0;
	pCmd->IeListLenHT = 0;
	pCmd->IeListLenVHT = 0;
	pCmd->IeListLenProprietary = 0;

	/***************************************************************************************************/
	/*IMPORTANT: When adding new IE or IE's fields, make sure Hostcmd and Generic_Beacon buffer in fw has enough size */
	/***************************************************************************************************/

	if (*(mib->QoSOptImpl)) {
		//why do we need info element in beacon, take out?????
		//      pCmd->IeListLen  += QoS_AppendWMEInfoElem/*QoS_AppendWMEParamElem*/(&(pCmd->IeList[retval]));

		if (vmacSta_p->wtp_info.WTP_enabled &&
		    vmacSta_p->wtp_info.extHtIE == true) {
			memcpy(&(pCmd->IeListHT[retval]),
			       vmacSta_p->wtp_info.HTCapIE,
			       vmacSta_p->wtp_info.HTCapIE[1] + 2);
			retval = (pCmd->IeListLenHT +=
				  vmacSta_p->wtp_info.HTCapIE[1] + 2);
			memcpy(&(pCmd->IeListHT[retval]),
			       vmacSta_p->wtp_info.addHTIE,
			       vmacSta_p->wtp_info.addHTIE[1] + 2);
			retval = (pCmd->IeListLenHT +=
				  vmacSta_p->wtp_info.addHTIE[1] + 2);
		} else {
			pCmd->IeListLenHT +=
				AddHT_IE(wlpptr->vmacSta_p,
					 (IEEEtypes_HT_Element_t *) & (pCmd->
								       IeListHT
								       [retval]));
			retval = pCmd->IeListLenHT;
			pCmd->IeListLenHT +=
				AddAddHT_IE(wlpptr->vmacSta_p,
					    (IEEEtypes_Add_HT_Element_t *) &
					    (pCmd->IeListHT[retval]));
			retval = pCmd->IeListLenHT;
		}

//#ifdef INTOLERANT40
		{
			extern UINT16 AddChanReport_IE(vmacApInfo_t * vmacSta_p,
						       IEEEtypes_ChannelReportEL_t
						       * pNextElement);
			pCmd->IeListLenHT +=
				AddChanReport_IE(wlpptr->vmacSta_p,
						 (IEEEtypes_ChannelReportEL_t *)
						 & (pCmd->IeListHT[retval]));
			retval = pCmd->IeListLenHT;
		}
//#endif

#ifdef COEXIST_20_40_SUPPORT
		/** We are only going to use 20/40 coexist for 2.4G band **/
		if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) &&
		    !((*(vmacSta_p->Mib802dot11->mib_ApMode) &
		       AP_MODE_BAND_MASK) >= AP_MODE_A_ONLY ||
		      (*(vmacSta_p->Mib802dot11->mib_ApMode) &
		       AP_MODE_BAND_MASK) <= AP_MODE_MIXED)) {
#if 0				//optional IE, not require at this time
			{
				extern UINT16 Add20_40_Coexist_IE(vmacApInfo_t *
								  vmacSta_p,
								  IEEEtypes_20_40_BSS_COEXIST_Element_t
								  *
								  pNextElement);

				pCmd->IeListLenHT +=
					Add20_40_Coexist_IE(wlpptr->vmacSta_p,
							    (IEEEtypes_20_40_BSS_COEXIST_Element_t
							     *) & (pCmd->
								   IeListHT
								   [retval]));
				retval = pCmd->IeListLenHT;
			}
			{
				extern UINT16
					Add20_40Interant_Channel_Report_IE
					(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t
					 * pNextElement);

				pCmd->IeListLenHT +=
					Add20_40Interant_Channel_Report_IE
					(wlpptr->vmacSta_p,
					 (IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t
					  *) & (pCmd->IeListHT[retval]));
				retval = pCmd->IeListLenHT;
			}
#endif
			{
				extern UINT16
					AddOverlap_BSS_Scan_Parameters_IE
					(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
					 * pNextElement);

				pCmd->IeListLenHT +=
					AddOverlap_BSS_Scan_Parameters_IE
					(wlpptr->vmacSta_p,
					 (IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
					  *) & (pCmd->IeListHT[retval]));
				retval = pCmd->IeListLenHT;

			}
			{
				extern UINT16 AddExtended_Cap_IE(vmacApInfo_t *
								 vmacSta_p,
								 IEEEtypes_Extended_Cap_Element_t
								 *
								 pNextElement);
				pCmd->IeListLenHT +=
					AddExtended_Cap_IE(wlpptr->vmacSta_p,
							   (IEEEtypes_Extended_Cap_Element_t
							    *) & (pCmd->
								  IeListHT
								  [retval]));
				retval = pCmd->IeListLenHT;
			}
		}

#endif
		/*Always add Extended Cap if in 5Ghz and VHT mode to pass wifi operating mode IE199 test */
#ifdef WNM
		extern void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket,
					     UINT8 attrib, UINT8 * OUI);
#endif //WNM
		if (*(vmacSta_p->Mib802dot11->mib_ApMode) >=
		    AP_MODE_5GHZ_11AC_ONLY) {
			extern UINT16 AddExtended_Cap_IE(vmacApInfo_t *
							 vmacSta_p,
							 IEEEtypes_Extended_Cap_Element_t
							 * pNextElement);
#ifdef WNM
			IEEEtypes_Extended_Cap_Element_t *pEC =
				FindIEWithinIEs(vmacSta_p->thisbeaconIEs.
						WSCData,
						vmacSta_p->thisbeaconIEs.Len,
						EXT_CAP_IE, NULL);

			if (pEC == NULL) {
				// Add the empty ExtCap only if it does not exist in thisbeaconIEs which will be added 
				//      in wlFwSetWscIE
				pCmd->IeListLenHT +=
					AddExtended_Cap_IE(wlpptr->vmacSta_p,
							   (IEEEtypes_Extended_Cap_Element_t
							    *) & (pCmd->
								  IeListHT
								  [retval]));
				retval = pCmd->IeListLenHT;
			}
#else
			pCmd->IeListLenHT +=
				AddExtended_Cap_IE(wlpptr->vmacSta_p,
						   (IEEEtypes_Extended_Cap_Element_t
						    *) & (pCmd->
							  IeListHT[retval]));
			retval = pCmd->IeListLenHT;
#endif //WNM
		}

		/*Add 11ac VHT supported IEs */
		if (*(mib->mib_ApMode) & AP_MODE_11AC) {
			if (vmacSta_p->wtp_info.WTP_enabled &&
			    vmacSta_p->wtp_info.extVhtIE == true) {
				memcpy(&(pCmd->IeListVHT[retvalVHT]),
				       vmacSta_p->wtp_info.vhtCapIE,
				       vmacSta_p->wtp_info.vhtCapIE[1] + 2);
				retvalVHT = (pCmd->IeListLenVHT +=
					     vmacSta_p->wtp_info.vhtCapIE[1] +
					     2);
				memcpy(&(pCmd->IeListVHT[retvalVHT]),
				       vmacSta_p->wtp_info.vhtInfoIE,
				       vmacSta_p->wtp_info.vhtInfoIE[1] + 2);
				retvalVHT = (pCmd->IeListLenVHT +=
					     vmacSta_p->wtp_info.vhtInfoIE[1] +
					     2);
			} else {
				pCmd->IeListLenVHT +=
					Build_IE_191(wlpptr->vmacSta_p,
						     (UINT8 *) & (pCmd->
								  IeListVHT
								  [retvalVHT]),
						     FALSE, 0);
				retvalVHT = pCmd->IeListLenVHT;

				pCmd->IeListLenVHT +=
					Build_IE_192(wlpptr->vmacSta_p,
						     (UINT8 *) & (pCmd->
								  IeListVHT
								  [retvalVHT]));
				retvalVHT = pCmd->IeListLenVHT;
			}
		}

#if 0				//#ifdef INTEROP
		pCmd->IeListLenProprietary +=
			Add_Generic_HT_IE(wlpptr->vmacSta_p,
					  (IEEEtypes_Generic_HT_Element_t *) &
					  (pCmd->
					   IeListProprietary
					   [retvalProprietary]));
		retvalProprietary = pCmd->IeListLenProprietary;
		pCmd->IeListLenProprietary +=
			Add_Generic_AddHT_IE(wlpptr->vmacSta_p,
					     (IEEEtypes_Generic_Add_HT_Element_t
					      *) & (pCmd->
						    IeListProprietary
						    [retvalProprietary]));
		/** For I_COMP only **/
		retvalProprietary = pCmd->IeListLenProprietary;
#endif

	}
	{
		//add M IE
		pCmd->IeListLenProprietary +=
			AddM_IE(wlpptr->vmacSta_p,
				(IEEEtypes_HT_Element_t *) & (pCmd->
							      IeListProprietary
							      [retvalProprietary]));
		retvalProprietary = pCmd->IeListLenProprietary;
	}

	{
		//add M Rptr IE 
		if (*(mib->mib_RptrMode)) {
			pCmd->IeListLenProprietary +=
				AddM_Rptr_IE(wlpptr->vmacSta_p,
					     (IEEEtypes_HT_Element_t *) &
					     (pCmd->
					      IeListProprietary
					      [retvalProprietary]));
			retvalProprietary = pCmd->IeListLenProprietary;
		}
	}
#ifdef MULTI_AP_SUPPORT
	if (mib->multi_ap_attr) {
		//add Multi-AP IE
		pCmd->IeListLenProprietary +=
			Add_MultiAP_IE(wlpptr->vmacSta_p,
				       (IEEEtypes_InfoElementHdr_t *) & (pCmd->
									 IeListProprietary
									 [retvalProprietary]),
				       WL_WLAN_TYPE_AP);
		retvalProprietary = pCmd->IeListLenProprietary;
	}
#endif /*MULTI_AP_SUPPORT */

	if (vmacSta_p->wtp_info.WTP_enabled &&
	    vmacSta_p->wtp_info.extPropIE == true) {
		memcpy(&(pCmd->IeListProprietary[retvalProprietary]),
		       vmacSta_p->wtp_info.propIE,
		       vmacSta_p->wtp_info.propIE[1] + 2);
		retvalProprietary = (pCmd->IeListLenProprietary +=
				     vmacSta_p->wtp_info.propIE[1] + 2);
	}
#ifdef MRVL_80211R
	if (mib->RSNConfigWPA2->WPA2Enabled ||
	    mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		if (vmacSta_p->MDIE[1] != 0) {
			memcpy(&(pCmd->IeListProprietary[retvalProprietary]),
			       vmacSta_p->MDIE, 5);
			retvalProprietary = (pCmd->IeListLenProprietary += 5);
		}
	}
#endif

#ifdef MV_CPU_BE
	pCmd->IeListLenHT = ENDIAN_SWAP16(pCmd->IeListLenHT);
	pCmd->IeListLenVHT = ENDIAN_SWAP16(pCmd->IeListLenVHT);
	pCmd->IeListLenProprietary = ENDIAN_SWAP16(pCmd->IeListLenProprietary);
#endif
	BFMRconfigVHT_HT(wlpptr, pCmd->IeListHT, pCmd->IeListVHT, NULL);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_IES);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
#endif /* #ifdef SOC_W906X */
}

#ifdef POWERSAVE_OFFLOAD
int
wlFwSetPowerSaveStation(struct net_device *netdev, u_int8_t StationPowerSave)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_POWERSAVESTATION *pCmd =
		(HostCmd_SET_POWERSAVESTATION *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, " wlFwSetPowerSaveStation %d",
			 StationPowerSave);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_POWERSAVESTATION));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_POWERSAVESTATION);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_SET_POWERSAVESTATION));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->NumberofPowersave = StationPowerSave;

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_SET_POWERSAVESTATION));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_POWERSAVESTATION);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetTIM(struct net_device *netdev, u_int16_t AID, u_int32_t Set)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_TIM *pCmd = (HostCmd_SET_TIM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, " wlFwSetTim %d %d", AID, Set);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_TIM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_TIM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_TIM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Aid = ENDIAN_SWAP16(AID);
	pCmd->Set = ENDIAN_SWAP32(Set);

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd, sizeof(HostCmd_SET_TIM));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_TIM);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwGetTIM(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_GET_TIM *pCmd = (HostCmd_GET_TIM *) & wlpptr->pCmdBuf[0];
	int retval = FAIL, i;
	unsigned long flags;

	//WLDBG_ENTER_INFO(DBG_LEVEL_1, "Optimization %d", mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_GET_TIM));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_TIM);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_GET_TIM));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd, sizeof(HostCmd_FW_GET_TIM));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_TIM);
	if (!retval) {
		for (i = 0; i < 10; i++)
			printk(" %x ", pCmd->TrafficMap[i]);
		//memcpy(pBcn, &pCmd->Bcn, pCmd->Bcnlen);
		//*pLen = pCmd->Bcnlen;
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif

extern int sprintf_hex_dump(u8 * pdest, u8 * psrc, UINT32 maxlen,
			    UINT32 maxbuflen);

int
wlexecuteCommand(struct net_device *netdev, unsigned short cmd)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef SOC_W906X
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	PFWCmdHdr pCmdHdr = (PFWCmdHdr) & wlpptr->pCmdBuf[0];
	char *logbuf = NULL;
	UINT32 size;
	UINT32 dbglen = 0;

	if (wlpd_p->smon.exceptionAbortCmdExec == 1) {
		//printk("Abort FWcmd:0x%04x, %s\n", cmd, netdev->name);
		return FAIL;
	}

	if (wlpd_p->smon.active) {
		if (!(logbuf = wl_kmalloc(HM_CMDBUF_SIZE * 4, GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating temp buffer for HM fail\n", __func__, __LINE__);
			return FAIL;
		}
	}
#endif

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "%s send cmd 0x%04x to firmware",
			 netdev->name, cmd);

#ifdef SC_PALLADIUM
	if (wlChkAdapter(netdev))	// && (!wlpptr->wlpd_p->inSendCmd))
#else
	if (wlChkAdapter(netdev) && (!wlpptr->wlpd_p->inSendCmd))
#endif
	{
#ifdef SOC_W906X
		UINT64 t1;
		UINT64 tsec, tms;

		WLDBG_FWCMD(DBG_LEVEL_1,
			    "%s:FWcmd:0x%04x, CpuID:%u, PID:%i, ProcName:\"%s\"\n",
			    netdev->name, cmd, smp_processor_id(), current->pid,
			    current->comm);
		t1 = xxGetTimeStamp();

		convert_tscale(t1, &tsec, &tms, NULL);
		if (wlpd_p->smon.active && wlpd_p->smon.ready) {
			size = (UINT32) sprintf(&logbuf[0],
						"[%llu.%llu]: %s     0x%04x    %u       %i    %s    ",
						tsec, tms, netdev->name, cmd,
						smp_processor_id(),
						current->pid, current->comm);
			wlmon_log_buffer(netdev, logbuf, size);
			//copy max the first 512 bytes of the cmd 
			dbglen = ((pCmdHdr->Length >
				   HM_CMDBUF_SIZE) ? HM_CMDBUF_SIZE : pCmdHdr->
				  Length);
			memcpy((UINT8 *) (wlpd_p->smon.pLastCmdBuf),
			       (UINT8 *) pCmdHdr, dbglen);
		}
#endif
		wlpptr->wlpd_p->inSendCmd = TRUE;
		wlsendCommand(netdev);
		if (wlwaitForComplete(netdev, 0x8000 | cmd)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "timeout");
#ifdef SOC_W906X
			WLDBG_FWCMD(DBG_LEVEL_1, "FWcmd:0x%04x timeout\n", cmd);
			if (wlpd_p->smon.active && wlpd_p->smon.ready) {
				u16 tmpcmd =
					(u16) (*(u16 *)
					       (wlpd_p->smon.pLastCmdBuf));

				//printk("Cmd buffer :cmd:0x%04x, cmd in buf:0x%04x\n", cmd, tmpcmd);

				size = (UINT32) sprintf(&logbuf[0],
							"[Alarm]:FWcmd:0x%04x timeout\nFWdmd dump(the first 512B max):\n",
							cmd);
				wlmon_log_buffer(netdev, logbuf, size);

				if (cmd != tmpcmd) {
					printk("\nCmd buffer Inconsistent, HM Ignores this cmd timeout:cmd:0x%04x, cmd in buf:0x%04x\n", cmd, tmpcmd);
				} else {
					//flag cmd timout event for HM to re-downloadd fw.
					wlpd_p->smon.exceptionAbortCmdExec = 1;
					wlpd_p->smon.exceptionCmdTOEvt_rcvd = 1;
					//printk("***Cmt Timeout....\n");
				}

				printk("Cmdbody dump (before execution):\n");
				mwl_hex_dump((UINT8 *) (wlpd_p->smon.
							pLastCmdBuf),
					     ((dbglen > 64) ? 64 : dbglen));

				size = (UINT32) sprintf_hex_dump(&logbuf[0],
								 (UINT8
								  *) (wlpd_p->
								      smon.
								      pLastCmdBuf),
								 dbglen,
								 HM_CMDBUF_SIZE
								 * 4);
				wlmon_log_buffer(netdev, &logbuf[0], size);

				if (logbuf) {
					wl_kfree(logbuf);
				}

			}
#endif
			wlpptr->wlpd_p->inSendCmd = FALSE;
			return TIMEOUT;
		}
		WLDBG_EXIT(DBG_LEVEL_0);
		wlpptr->wlpd_p->inSendCmd = FALSE;
#ifdef SOC_W906X
		WLDBG_FWCMD(DBG_LEVEL_1, "Cmd completed time:%u usec\n",
			    (UINT32) (xxGetTimeStamp() - t1));
		if (wlpd_p->smon.active && wlpd_p->smon.ready) {
			UINT32 tdif = (UINT32) (xxGetTimeStamp() - t1);

			if (tdif > HM_CMD_RESP_THRESHOLD) {
				size = (UINT32) sprintf(&logbuf[0],
							"%u [Alarm]:long latency\n",
							tdif);
			} else {
				size = (UINT32) sprintf(&logbuf[0], "%u\n",
							tdif);
			}
			wlmon_log_buffer(netdev, logbuf, size);
		}

		if (logbuf) {
			wl_kfree(logbuf);
		}
#endif
		return SUCCESS;
	}
#ifdef SOC_W906X
	if (logbuf) {
		wl_kfree(logbuf);
	}
#endif

	if (wlpptr->wlpd_p->inSendCmd == TRUE) {
		wlpptr->wlpd_p->inSendCmd = FALSE;
		return SUCCESS;
	}
	wlpptr->wlpd_p->inSendCmd = FALSE;
	WLDBG_EXIT_INFO(DBG_LEVEL_0, "no adapter plugged in");
	return FAIL;

}

static void
wlsendCommand(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef SOC_W906X
	unsigned int reg_gen_ptr = wlpptr->wlpd_p->reg.gen_ptr;
	unsigned int reg_h2a_int_events = wlpptr->wlpd_p->reg.h2a_int_events;

	wl_util_writel(netdev, wlpptr->wlpd_p->pPhysCmdBuf, wlpptr->ioBase1 + reg_gen_ptr);
	wl_util_writel(netdev, MACREG_H2ARIC_BIT_DOOR_BELL, wlpptr->ioBase1 + reg_h2a_int_events);
#else
	wl_util_writel(netdev, wlpptr->wlpd_p->pPhysCmdBuf, wlpptr->ioBase1+MACREG_REG_GEN_PTR);
	wl_util_writel(netdev, MACREG_H2ARIC_BIT_DOOR_BELL,
	       wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
#endif /* #ifdef SOC_W906X */
}

static char *cmdrespStr[] = {
	"Success",		//HostCmd_RESULT_OK
	"Error",		//HostCmd_RESULT_ERROR
	"Not Supported",	//HostCmd_RESULT_NOT_SUPPORT
	"Pending",		//HostCmd_RESULT_PENDING
	"Busy",			//HostCmd_RESULT_BUSY
	"Partial Data",		//HostCmd_RESULT_PARTIAL_DATA
	"MAC cmd buffer full",	//HostCmd_RESULT_SMAC_CMD_BUFF_FULL
	"BSS Index Invalid",	//HostCmd_RESULT_BSS_INDEX_INVALID
	"BSS entry not found",	//HostCmd_RESULT_BSS_NOT_FOUND
	"STA entry not existed",	//HostCmd_RESULT_STA_NOT_FOUND
	"Cmd Aborted",		//HostCmd_RESULT_ABORT
	"STA Index Invalid",	//HostCmd_RESULT_STA_INDEX_INVALID
	"OFFCHAN BCN GUARD",	//HostCmd_RESULT_OFFCHAN_BCN_GUARD
	"OFFCHAN IN PROCESS",	//HostCmd_RESULT_OFFCHAN_IN_PROCESS
	"Unknown"		//HostCmd_RESULT_LAST; Error code not defined
};

static UINT8 *
getCmdRspErrorStr(UINT16 reason)
{
	if (reason < HostCmd_RESULT_LAST)
		return cmdrespStr[reason];
	else
		return cmdrespStr[HostCmd_RESULT_LAST];
}

static int
wlwaitForComplete(struct net_device *netdev, u_int16_t cmdCode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int currIteration = MAX_WAIT_FW_COMPLETE_ITERATIONS;
	volatile unsigned short intCode = 0;

	do {
		intCode = ENDIAN_SWAP16(wlpptr->pCmdBuf[0]);
		udelay(1);
#ifdef SC_PALLADIUM
	} while ((intCode != cmdCode));	// && (--currIteration));
#else
	} while ((intCode != cmdCode) && (--currIteration));
#endif

	if (currIteration == 0) {
		WLDBG_INFO(DBG_LEVEL_0, "%s: cmd 0x%04x=%s timed out\n",
			   wlgetDrvName(netdev), cmdCode,
			   wlgetCmdString(cmdCode));
		printk("%s: cmd 0x%04x timed out\n", wlgetDrvName(netdev),
		       cmdCode);
		printk("The Last poll Cmd code in pCmdBuf[0]:0x%04x\n",
		       intCode);
		printk("pCmdBuf dump:\n");
		mwl_hex_dump((u8 *) & wlpptr->pCmdBuf[0], 64);
		return TIMEOUT;
	}
#ifdef SOC_W906X
#ifdef WL_DEBUG			/* When SC5 commans are ready, will disabled this debug code */
	else {
		FWCmdHdr *pCmdHdr = (FWCmdHdr *) & wlpptr->pCmdBuf[0];
		u_int16_t result = ENDIAN_SWAP16(pCmdHdr->Result);

		if (result) {
			u_int16_t length = ENDIAN_SWAP16(pCmdHdr->Length);

			if (length > 32)
				length = 32;

			WLDBG_FWCMD(DBG_LEVEL_1,
				    "%s: cmd 0x%04x response seq# %d error code %d reason: %s\n",
				    wlgetDrvName(netdev), intCode,
				    pCmdHdr->SeqNum, result,
				    getCmdRspErrorStr(result));
			WLDBG_FWCMD_HEXDUMP(DBG_LEVEL_1,
					    (void *)&wlpptr->pCmdBuf[0],
					    length);
		}
	}
#endif
#endif /* #ifdef SOC_W906X */
	return SUCCESS;
}

#ifdef WL_DEBUG
static char *
wlgetCmdString(u_int16_t cmd)
{
	int maxNumCmdEntries = 0;
	int currCmd = 0;
	static const struct {
		u_int16_t cmdCode;
		char *cmdString;
	} cmds[] = {
		{
		HostCmd_CMD_GET_HW_SPEC, "GetHwSpecifications"}, {
		HostCmd_CMD_802_11_RADIO_CONTROL, "SetRadio"}, {
		HostCmd_CMD_802_11_RF_ANTENNA, "SetAntenna"}, {
		HostCmd_CMD_802_11_RTS_THSD, "SetStationRTSlevel"}, {
		HostCmd_CMD_SET_INFRA_MODE, "SetInfraMode"}, {
		HostCmd_CMD_SET_RATE, "SetRate"}, {
		HostCmd_CMD_802_11_SET_SLOT, "SetStationSlot"}, {
		HostCmd_CMD_802_11_RF_TX_POWER, "SetTxPower"}, {
		HostCmd_CMD_SET_PRE_SCAN, "SetPrescan"}, {
		HostCmd_CMD_SET_POST_SCAN, "SetPostscan"}, {
		HostCmd_CMD_MAC_MULTICAST_ADR, "SetMulticastAddr"}, {
		HostCmd_CMD_SET_WEP, "SetWepEncryptionKey"}, {
		HostCmd_CMD_802_11_PTK, "SetPairwiseTemporalKey"}, {
		HostCmd_CMD_802_11_GTK, "SetGroupTemporalKey"}, {
		HostCmd_CMD_SET_MAC_ADDR, "SetMACaddress"}, {
		HostCmd_CMD_SET_BEACON, "SetStationBeacon"}, {
		HostCmd_CMD_AP_BEACON, "SetApBeacon"}, {
		HostCmd_CMD_SET_FINALIZE_JOIN, "SetFinalizeJoin"}, {
		HostCmd_CMD_SET_AID, "SetAid"}, {
		HostCmd_CMD_SET_RF_CHANNEL, "SetChannel"}, {
		HostCmd_CMD_802_11_GET_STAT, "GetFwStatistics"}, {
		HostCmd_CMD_BSS_START, "SetBSSstart"}, {
		HostCmd_CMD_UPDATE_TIM, "SetTIM"}, {
		HostCmd_CMD_BROADCAST_SSID_ENABLE, "SetBroadcastSSID"}, {
		HostCmd_CMD_WDS_ENABLE, "SetWDS"}, {
		HostCmd_CMD_SET_BURST_MODE, "SetBurstMode"}, {
		HostCmd_CMD_SET_G_PROTECT_FLAG, "SetGprotectionFlag"}, {
	HostCmd_CMD_802_11_BOOST_MODE, "SetBoostMode"},};

	maxNumCmdEntries = sizeof(cmds) / sizeof(cmds[0]);
	for (currCmd = 0; currCmd < maxNumCmdEntries; currCmd++) {
		if ((cmd & 0x7fff) == cmds[currCmd].cmdCode) {
			return cmds[currCmd].cmdString;
		}
	}
	return "unknown";
}

static char *
wlgetCmdResultString(u_int16_t result)
{
	int maxNumResultEntries = 0;
	int currResult = 0;
	static const struct {
		u_int16_t resultCode;
		char *resultString;
	} results[] = {
		{
		HostCmd_RESULT_OK, "ok"}, {
		HostCmd_RESULT_ERROR, "general error"}, {
		HostCmd_RESULT_NOT_SUPPORT, "not supported"}, {
		HostCmd_RESULT_PENDING, "pending"}, {
		HostCmd_RESULT_BUSY, "ignored"}, {
	HostCmd_RESULT_PARTIAL_DATA, "incomplete"},};

	maxNumResultEntries = sizeof(results) / sizeof(results[0]);
	for (currResult = 0; currResult < maxNumResultEntries; currResult++) {
		if (result == results[currResult].resultCode) {
			return results[currResult].resultString;
		}
	}
	return "unknown";
}
#endif

extern char *DRV_NAME;
static char *
wlgetDrvName(struct net_device *netdev)
{
	if (strchr(netdev->name, '%')) {
		return DRV_NAME;
	}
	return netdev->name;
}

#ifdef SOC_W906X

u_int8_t
GetSecondChannel(u_int8_t Channel, u_int8_t bw)
{
	int i;

	if (bw == CH_160_MHz_WIDTH) {
		for (i = 0;
		     i <
		     domainGetSizeOfGrpChList160Mhz() /
		     sizeof(GRP_CHANNEL_LIST_160Mhz); i++) {
			if (channel_exists
			    (Channel, GrpChList160Mhz[i].channelEntry, 8)) {
				if (Channel <
				    GrpChList160Mhz[i].channelEntry[4])
					return GrpChList160Mhz[i].
						channelEntry[4];
				else
					return GrpChList160Mhz[i].
						channelEntry[0];
			}
		}
	} else {
		for (i = 0;
		     i <
		     domainGetSizeOfGrpChList80Mhz() /
		     sizeof(GRP_CHANNEL_LIST_80Mhz); i++) {
			if (channel_exists
			    (Channel, GrpChList80Mhz[i].channelEntry,
			     4) == FALSE) {
				return GrpChList80Mhz[i].channelEntry[0];
			}
		}
	}
	return 0;
}

int
wlchannelSet(struct net_device *netdev, int channel, int Channel2,
	     CHNL_FLAGS chanflag, u_int8_t initRateTable)
#else
int
wlchannelSet(struct net_device *netdev, int channel, CHNL_FLAGS chanflag,
	     u_int8_t initRateTable)
#endif
{
	//      struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	WLDBG_ENTER(DBG_LEVEL_0);

#ifdef SOC_W906X
	if (wlFwSetChannel(netdev, channel, Channel2, chanflag, initRateTable)) {
#else
	if (wlFwSetChannel(netdev, channel, chanflag, initRateTable)) {
#endif
		WLDBG_WARNING(DBG_LEVEL_0, "channel set failed");
	}

	WLDBG_EXIT(DBG_LEVEL_0);
	return SUCCESS;
}

int
wlFwApplyChannelSettings(struct net_device *netdev)
{
	int retval = SUCCESS;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	//      MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

#ifdef SOC_W906X
	if (PhyDSSSTable->SecChan != 0 &&
	    PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) {
		/* swap primary and 2nd channel according to fw design */
		retval = wlchannelSet(netdev, PhyDSSSTable->SecChan,
				      PhyDSSSTable->CurrChan,
				      PhyDSSSTable->Chanflag, 1);
	} else {
		retval = wlchannelSet(netdev, PhyDSSSTable->CurrChan,
				      PhyDSSSTable->SecChan,
				      PhyDSSSTable->Chanflag, 1);
	}
	if (retval != SUCCESS) {
#else
	if (wlchannelSet
	    (netdev, PhyDSSSTable->CurrChan, PhyDSSSTable->Chanflag, 1)) {
#endif
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting channel");
		retval = FAIL;
	}
	if (wlFwSetApBeacon(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting AP beacon");
		retval = FAIL;
	}
	if (wlFwSetAPBss(netdev, WL_ENABLE)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling AP bss");
		retval = FAIL;
	}
	if (WlLoadRateGrp(netdev)) {
		WLDBG_WARNING(DBG_LEVEL_0, "set per rate power fail");
		retval = FAIL;
	}
	if (wlFwSetSpectrumMgmt
	    (netdev, mib_SpectrumMagament_p->spectrumManagement)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling spectrum management");
		retval = FAIL;
	}

	if (wlFwSetCountryCode(netdev, mib_SpectrumMagament_p->countryCode)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling country code info");
		retval = FAIL;
	}
	return retval;
}

#ifndef SOC_W906X
static BOOLEAN
AnyDevAmsduEnabled(struct net_device *netdev)
{
#if defined(MBSS)
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *wlpptr1;
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;
	int i = 0;
	while (i <= bss_num) {
		if (wlpptr->vdev[i]) {
			wlpptr1 =
				NETDEV_PRIV_P(struct wlprivate,
					      wlpptr->vdev[i]);
			vmacSta_p = wlpptr1->vmacSta_p;
			mib = vmacSta_p->Mib802dot11;
			if (wlpptr->vdev[i]->flags & IFF_RUNNING) {
				if (*(mib->pMib_11nAggrMode) &
				    WL_MODE_AMSDU_TX_MASK)
					return TRUE;
			}
		}
		i++;
	}
#endif
	return FALSE;
}
#endif
int
wlFwApplySettings(struct net_device *netdev)
{
	int retval = SUCCESS;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_802DOT11 *mib1 = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable1 = mib1->PhyDSSSTable;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament1_p = mib1->SpectrumMagament;
	UINT8 *mib_guardInterval_p = mib->mib_guardInterval;
	extern int wlFwSet11N_20_40_Switch(struct net_device *netdev,
					   UINT8 mode);

#ifdef MRVL_DFS
	BOOLEAN bChannelChanged = FALSE;
	BOOLEAN bBandWidthChanged = FALSE;
	UINT8 currDFSMode = 0, newDFSMode = 0;
	DfsAp *me;
	DfsApDesc *dfsDesc_p = NULL;

	/* Check if channel is going to be modified. DFS will be kicked
	   in only if a channel change occur here.
	 */
#ifdef SOC_W906X
	if ((PhyDSSSTable->CurrChan != PhyDSSSTable1->CurrChan) ||
	    (PhyDSSSTable->SecChan != PhyDSSSTable1->SecChan)) {
		bChannelChanged = TRUE;
	}
	if ((PhyDSSSTable->Chanflag.ChnlWidth !=
	     PhyDSSSTable1->Chanflag.ChnlWidth) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth2 !=
	     PhyDSSSTable1->Chanflag.ChnlWidth2)) {
		bBandWidthChanged = TRUE;
	}
#else
	if (PhyDSSSTable->CurrChan != PhyDSSSTable1->CurrChan) {
		bChannelChanged = TRUE;
	}
	if (PhyDSSSTable->Chanflag.ChnlWidth !=
	    PhyDSSSTable1->Chanflag.ChnlWidth) {
		bBandWidthChanged = TRUE;
	}
#endif /* #ifdef SOC_W906X */
	currDFSMode = mib_SpectrumMagament_p->spectrumManagement;
	newDFSMode = mib_SpectrumMagament1_p->spectrumManagement;
	if ((*mib1->mib_autochannel == 1) && newDFSMode &&
	    !vmacSta_p->dfsCacExp) {
		/* if autochannel == 2, it will scan DFS channel and don't clear NOCList */
		newDFSMode = vmacSta_p->autochannelstarted;
	}
#endif

#ifdef SOC_W906X
	if ((PhyDSSSTable1->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) &&
	    (PhyDSSSTable1->SecChan == 0)) {
		PhyDSSSTable1->Chanflag.radiomode = RADIO_MODE_80p80;
		PhyDSSSTable1->Chanflag.ChnlWidth2 = CH_80_MHz_WIDTH;
		PhyDSSSTable1->SecChan =
			GetSecondChannel(PhyDSSSTable1->CurrChan,
					 CH_160_MHz_WIDTH);
		PhyDSSSTable1->Chanflag.FreqBand2 =
			PhyDSSSTable->Chanflag.FreqBand;

		if (PhyDSSSTable1->SecChan == 0) {
			PhyDSSSTable1->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
			PhyDSSSTable1->SecChan =
				GetSecondChannel(PhyDSSSTable->CurrChan,
						 CH_80_MHz_WIDTH);

			printk("Can't find available secChan, change to 80+80 chan=%d secChan=%d bw=%d bw2=%d\n", PhyDSSSTable1->CurrChan, PhyDSSSTable1->SecChan, PhyDSSSTable1->Chanflag.ChnlWidth, PhyDSSSTable1->Chanflag.ChnlWidth2);
		}
	}
#endif

	mib_Update();

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return retval;
	}
#endif
#ifdef SINGLE_DEV_INTERFACE
	if (wlFwSetMacAddr(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting dev mac");
		retval = FAIL;
	}
#endif
	if (wlFwGetRegionCode(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "getting Region code");
		retval = FAIL;
	}
	if (wlFwSetAntenna(netdev, WL_ANTENNATYPE_RX)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting RX antenna");
		retval = FAIL;
	}
	if (wlFwSetAntenna(netdev, WL_ANTENNATYPE_TX)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting TX antenna");
		retval = FAIL;
	}
	if (wlFwSetHTStbc(netdev, *mib->mib_HtStbc)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting HT STBC");
		retval = FAIL;
	}
#ifndef SOC_W906X
	if (wlFwSetBWSignalType(netdev, *mib->mib_bwSignaltype, 0)) {	//3rd input of function is for CTS BW signalling test
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting BW Signal TYPE");
		retval = FAIL;
	}
#endif
	if (wlFwSetRadio(netdev, WL_ENABLE, mib->StationConfig->mib_preAmble)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting auto preamble");
		retval = FAIL;
	}
#ifdef SOC_W906X
#ifdef CONCURRENT_DFS_SUPPORT
	if (wlpptr->wlpd_p->ext_scnr_en && wlpptr->wlpd_p->pdfsApMain) {
		DfsApDesc *dfsDesc_p;

		dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;
#if 1
		mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_7x7p1x1;
		mib->PhyDSSSTable->Chanflag.FreqBand2 =
			mib->PhyDSSSTable->Chanflag.FreqBand;
		mib->PhyDSSSTable->Chanflag.ChnlWidth2 =
			mib->PhyDSSSTable->Chanflag.ChnlWidth;
		mib->PhyDSSSTable->SecChan = dfsDesc_p->CtlChanInfo.channel;

		if (!bChannelChanged)
			mib->PhyDSSSTable->CurrChan =
				dfsDesc_p->currChanInfo.channel;
		else
			dfsDesc_p->currChanInfo.channel =
				mib->PhyDSSSTable->CurrChan;

		if (bBandWidthChanged)
			dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth =
				dfsDesc_p->currChanInfo.chanflag.ChnlWidth =
				mib->PhyDSSSTable->Chanflag.ChnlWidth;
#endif
		if (UpdateCurrentChannelInMIB
		    (vmacSta_p, mib->PhyDSSSTable->CurrChan)) {
			mib_Update();

			if (wlchannelSet
			    (netdev, dfsDesc_p->CtlChanInfo.channel,
			     dfsDesc_p->currChanInfo.channel,
			     dfsDesc_p->CtlChanInfo.chanflag, 1)) {
				WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting channel");
				retval = FAIL;
			}
		}
	} else
#endif /* CONCURRENT_DFS_SUPPORT */
	{
		if (PhyDSSSTable->SecChan != 0 &&
		    PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) {
			/* swap primary and 2nd channel according to fw design */
			retval = wlchannelSet(netdev, PhyDSSSTable->SecChan,
					      PhyDSSSTable->CurrChan,
					      PhyDSSSTable->Chanflag, 1);
		} else if (UpdateCurrentChannelInMIB
			   (vmacSta_p, mib->PhyDSSSTable->CurrChan)) {
			mib_Update();
			retval = wlchannelSet(netdev, PhyDSSSTable->CurrChan,
					      PhyDSSSTable->SecChan,
					      PhyDSSSTable->Chanflag, 1);
		}
		if (retval != SUCCESS) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting channel");
			retval = FAIL;
		}
	}
#else /* SOC_W906X */
	if (wlchannelSet
	    (netdev, PhyDSSSTable->CurrChan, PhyDSSSTable->Chanflag, 1)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting channel");
		retval = FAIL;
	}
#endif /* SOC_W906X */
	if (wlFwSetRegionCode(netdev, *(mib->mib_regionCode))) {
		WLDBG_WARNING(DBG_LEVEL_1, "setting region code");
		retval = FAIL;
	}

	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_BAND_MASK) <
	    AP_MODE_A_ONLY)
		wlFwSet11N_20_40_Switch(vmacSta_p->dev,
					((PhyDSSSTable1->Chanflag.ChnlWidth ==
					  CH_20_MHz_WIDTH) ? 0 : 1));

#ifdef MRVL_DFS
	/*Ignore the changes among CAC period */
	me = wlpptr->wlpd_p->pdfsApMain;
	if ((me != NULL) && (wlpptr->master == NULL)) {
		dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	}
	if (dfsDesc_p && dfsDesc_p->cac_complete == 1) {
	} else {
		if (DecideDFSOperation
		    (netdev, bChannelChanged, bBandWidthChanged, currDFSMode,
		     newDFSMode, mib)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_1, "DFS Operation");
			retval = FAIL;
		}
	}
#endif //MRVL_DFS
#ifndef SOC_W906X
	if (wlFwGetPwrCalTable(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_1, "getting cal power table");
		retval = FAIL;
	}
	if (wlFwSetMaxTxPwr(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting Max Tx Power");
		retval = FAIL;
	}
	if (wlFwSetTxPower(netdev, HostCmd_ACT_GEN_SET_LIST, 0)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting tx power");
		retval = FAIL;
	}
#endif
	if (wlFwSetAntenna(netdev, WL_ANTENNATYPE_TX2)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting TX antenna2");
		retval = FAIL;
	}
	if (wlFwSetCDD(netdev, *mib->mib_CDD)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting CDD");
		retval = FAIL;
	}
#ifndef SOC_W906X
	if (wlFwSetIEs(netdev)) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting IEs");
		retval = FAIL;
	}
	if (wlFwSetAPBcastSSID(netdev, *(mib->mib_broadcastssid))) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting hidden ssid");
		retval = FAIL;
	}
	if (wlFwSetWmm(netdev, *(mib->QoSOptImpl))) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting qos option");
		retval = FAIL;
	}
#endif
	{
		struct wlprivate *wlp =
			NETDEV_PRIV_P(struct wlprivate,
				      wlpptr->wlpd_p->rootdev);
		struct net_device *vdev;
		int i;

		for (i = 0; i < MAX_VMAC_INSTANCE_AP + 2; i++) {
			vdev = wlp->vdev[i];

			if (wlFwSetApMode(vdev, *(mib->mib_ApMode))) {
				WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting AP MODE");
				retval = FAIL;
			}
		}
	}

	if (wlFwHTGI(netdev, *mib_guardInterval_p)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting HT GI");
		retval = FAIL;
	}
	if (wlFwSetAdaptMode(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting Adpat mode");
		retval = FAIL;
	}
#ifndef SOC_W906X
	if (wlFwSetCSAdaptMode(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting CS Adpat mode");
		retval = FAIL;
	}
#endif
#ifdef RXPATHOPT
	if (wlFwSetRxPathOpt(netdev, *(mib->mib_RxPathOpt))) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting RxPathOpt");
		retval = FAIL;
	}
#endif

#ifdef V6FW
	/* For V5 and V6 firmware need to enable DwdsStaMode for AP operation. */
	/* This can be disabled if switched to station mode later. */
	if (wlFwSetDwdsStaMode(netdev, 1)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting DwdsStaMode mode");
		retval = FAIL;
	}
#endif
	//always turn flush timer off, and let VAP to turn it on.
	if (wlFwSetFwFlushTimer(netdev, 0)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting Fw Flush timer");
		retval = FAIL;
	}
	if (*(mib->QoSOptImpl)) {
		/** update qos param to fw here **/
		int i = 0;
		for (i = 0; i < 4; i++) {

			/* NOTE: Sequence of hostcmd:
			   wlFwSetEdcaParam
			   wlFwSetOptimizationLevel if using HiPerfMode
			   wlFwSetRate if using FixedRate
			 */
			if (wlFwSetEdcaParam
			    (netdev, i, mib_QAPEDCATable[i].QAPEDCATblCWmin,
			     mib_QAPEDCATable[i].QAPEDCATblCWmax,
			     mib_QAPEDCATable[i].QAPEDCATblAIFSN,
			     mib_QAPEDCATable[i].QAPEDCATblTXOPLimit)) {
				WLDBG_EXIT_INFO(DBG_LEVEL_0,
						"setting qos option");
				retval = FAIL;
			}
		}

	}
#ifdef SINGLE_DEV_INTERFACE
	if (wlFwSetApBeacon(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting AP beacon");
		retval = FAIL;
	}
#endif
	/* NOTE: Sequence of hostcmd:
	   wlFwSetEdcaParam
	   wlFwSetOptimizationLevel if using HiPerfMode
	   wlFwSetRate if using FixedRate
	 */
#ifndef SOC_W906X
	if (wlFwSetOptimizationLevel(netdev, *(mib->mib_optlevel))) {
		WLDBG_WARNING(DBG_LEVEL_0, "set Optimization level");
		retval = FAIL;
	}
#endif
	/* NOTE: Sequence of hostcmd:
	   wlFwSetEdcaParam
	   wlFwSetOptimizationLevel if using HiPerfMode
	   wlFwSetRate if using FixedRate
	 */
	if (wlFwSetRate(netdev, *(mib->mib_enableFixedRateTx))) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting tx rate");
		retval = FAIL;
	}
	if (wlFwSetRTSThreshold(netdev, *(mib->mib_RtsThresh))) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting rts threshold");
		retval = FAIL;
	}
#ifdef SINGLE_DEV_INTERFACE
	if (wlFwSetAPBss(netdev, WL_ENABLE)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling AP bss");
		retval = FAIL;
	}
#endif
	if (WlLoadRateGrp(netdev)) {
		WLDBG_WARNING(DBG_LEVEL_0, "set per rate power fail");
		retval = FAIL;
	}
	if (wlFwOBW16_11b(netdev, mib1->obw16_11b_val) == FAIL) {
		WLDBG_WARNING(DBG_LEVEL_0, "11b OBW set fail");
		retval = FAIL;
	}

	if (mib->rxsop_ed_threshold1 || mib->rxsop_ed_threshold2) {
		if (wlFwNewDP_RxSOP
		    (netdev, 2, mib->rxsop_ed_threshold1,
		     mib->rxsop_ed_threshold2) == FAIL) {
			WLDBG_WARNING(DBG_LEVEL_0, "set RxSOP EDMAC fail");
			retval = FAIL;
		}
	}
	if (mib->rxsop_cck_threshold1) {
		if (wlFwNewDP_RxSOP(netdev, 4, mib->rxsop_cck_threshold1, 0) ==
		    FAIL) {
			WLDBG_WARNING(DBG_LEVEL_0, "set RxSOP CCK fail");
			retval = FAIL;
		}
	}

	{
		extern int set_sta_aging_time(vmacApInfo_t * vmacSta_p,
					      int minutes);
		set_sta_aging_time(vmacSta_p, *(mib->mib_agingtime) / 60);
	}
	{
		extern int set_rptrSta_aging_time(vmacApInfo_t * vmacSta_p,
						  int minutes);
		set_rptrSta_aging_time(vmacSta_p,
				       *(mib->mib_agingtimeRptr) / 60);
	}

#ifdef IEEE80211K
	/* ignore, set cap_ie & rrm_ie from driver */
	wlFwSetRadioResourceMgmt(netdev, *(mib->mib_rrm));
	if (*(mib->mib_rrm)) {
		Enable_MSAN_timer(netdev);
	} else {
		Disable_MSAN_timer(netdev);
	}
#endif

	if (wlFwSetSpectrumMgmt
	    (netdev, mib_SpectrumMagament_p->spectrumManagement)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling spectrum management");
		retval = FAIL;
	}
	/* power constraint ino IE should appear in beacon only on 5GHz */
	if ((mib_SpectrumMagament_p->spectrumManagement &&
	     (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ))
		) {
		if (wlFwSetPowerConstraint
		    (netdev, mib_SpectrumMagament_p->powerConstraint)) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "setting power constraint info element");
			retval = FAIL;
		}
	}

	if (mib_SpectrumMagament_p->multiDomainCapability) {
		if (wlFwSetCountryCode
		    (netdev, mib_SpectrumMagament_p->countryCode)) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "setting country code info element");
			retval = FAIL;
		}
	} else {
		/* remove the country code element from beacon */
		if (wlFwSetCountryCode(netdev, 0)) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "setting country code info element");
			retval = FAIL;
		}
	}

	if (wlFwSetNProt(netdev, *(mib->mib_htProtect))) {
		WLDBG_WARNING(DBG_LEVEL_0, "set N protection");
		retval = FAIL;
	}
	if (*(mib->mib_rifsQNum) != 0)
		if (wlFwSetRifs(netdev, *(mib->mib_rifsQNum))) {
			WLDBG_WARNING(DBG_LEVEL_1, "set RIFS");
			retval = FAIL;
		}
#ifdef CLIENTONLY
	wlFwSetNewStn(netdev, vmacSta_p->macStaAddr, 0, 0, StaInfoDbActionAddEntry, NULL, 0, 0, 0);	//add new station
	wlFwSetSecurity(netdev, vmacSta_p->macStaAddr);
	if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled) {
		KeyMgmtInit(vmacSta_p);
	}
#endif
#ifdef SINGLE_DEV_INTERFACE
	SendResetCmd(wlpptr->vmacSta_p, 0);
#ifndef SOC_W906X
#ifdef WDS_FEATURE
	wlFwSetWdsMode(netdev);
#endif
#endif /* #ifndef SOC_W906X */
#endif

#ifndef SOC_W906X
	if (wlFwSetConsecTxFailLimit(netdev, *(mib->mib_consectxfaillimit))) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0,
				"setting consecutive txfail limit");
		retval = FAIL;
	}
	if (wlFwNewDP_OffChannel_Start(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Off Chanel start fail");
		retval = FAIL;
	}
	if (wlFwNewDP_sensorD_init(netdev, 0, 0)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Sensord shared mem start fail");
		retval = FAIL;
	}

	if (wlFwNewDP_DMAThread_start(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "FW DMA thread start fail");
		retval = FAIL;
	}
#endif
	if (wlFwSetBFType(netdev, *mib->mib_bftype)) {	//place at end so fw doesn't overwrite mac 0xd78
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting BF TYPE");
		retval = FAIL;
	}
#ifdef SOC_W906X
	ListInit(&wlpptr->wlpd_p->offChanList);
	TimerInit(&wlpptr->wlpd_p->offChanCooldownTimer);
#else //906X off-channel
	ListInit(&wlpptr->wlpd_p->ReqIdList);
#endif //906X off-channel

#ifdef SOC_W906X
	if (wlFwSetBeamChange(netdev, !(*(mib->mib_beamChange_disable)))) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Set Beam Change fail");
		retval = FAIL;
	}
#endif

#ifdef AIRTIME_FAIRNESS
	if (wlFwAtfEnable(netdev, *mib->mib_atf_enable)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Set ATF enable fail");
		retval = FAIL;
	}
	if (wlFwSetAtfCfg(netdev, ATF_PARAM_VI, *mib->mib_atf_cfg_vi)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Set ATF CFG VI fail");
		retval = FAIL;
	}
	if (wlFwSetAtfCfg(netdev, ATF_PARAM_BE, *mib->mib_atf_cfg_be)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Set ATF CFG BE fail");
		retval = FAIL;
	}
	if (wlFwSetAtfCfg(netdev, ATF_PARAM_BK, *mib->mib_atf_cfg_bk)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Set ATF CFG BK fail");
		retval = FAIL;
	}
	if (wlFwSetAtfCfg(netdev, ATF_PARAM_AIRTIME, *mib->mib_atf_cfg_airtime)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "Set ATF CFG Airtime fail");
		retval = FAIL;
	}
#endif /* AIRTIME_FAIRNESS */

#ifdef SINGLE_DEV_INTERFACE
	/*Call this at the end after wlFwSetAPBss */
	SendBFMRconfig(netdev);
#endif

	return SUCCESS;
}

int
wlFwMultiBssApplySettings(struct net_device *netdev)
{
	int retval = SUCCESS;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	//MIB_PHY_DSSS_TABLE *PhyDSSSTable=mib->PhyDSSSTable;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;

#ifdef MRVL_WSC
	WSC_COMB_IE_t *combIE = NULL;
#endif

	if (vmacSta_p->master &&
	    (vmacSta_p->master->preautochannelfinished == 0) &&
	    (*(mib->mib_autochannel) != 0)) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Don't enable AP bss when enable autochannel and in scanning");
		return FAIL;
	}

	if (wlpptr->wlpd_p->repeaterUpdateChannelWidth) {
		vmacSta_p->ShadowMib802dot11->PhyDSSSTable->Chanflag.ChnlWidth =
			wlpptr->wlpd_p->repeaterUpdateChannelWidth;
	}
#ifdef MRVL_DFS
	/* If currently DFS scanning no need to apply MBSS settings */
	if ((DfsGetCurrentState(wlpptr->wlpd_p->pdfsApMain)) == DFS_STATE_SCAN) {
		/* Current State is DFS_STATE_SCAN. Beacons should not be sent out.
		   So do not proceed further.
		 */
		return SUCCESS;
	}
#endif //MRVL_DFS
#ifdef IEEE80211K
	*(vmacSta_p->ShadowMib802dot11->mib_rrm) =
		*(vmacSta_p->master->Mib802dot11->mib_rrm);
	*(vmacSta_p->ShadowMib802dot11->mib_quiet) =
		*(vmacSta_p->master->Mib802dot11->mib_quiet);
#endif /* IEEE80211K */

	mib_Update();
	/* in case virtual interface MAC addr changed (by cmd "bssid" etc.) */
	memcpy(wlpptr->hwData.macAddr, netdev->dev_addr,
	       sizeof(IEEEtypes_MacAddr_t));

#ifdef SOC_W906X
	macMgmtMlme_ResetProbeRspBuf(vmacSta_p);
#endif

	if (wlFwSetIEs(netdev)) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting IEs");
		retval = FAIL;
	}
#ifndef SOC_W906X
	if (wlFwSetAPBcastSSID(netdev, *(mib->mib_broadcastssid))) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting hidden ssid");
		retval = FAIL;
	}
#endif
	if (wlFwSetApBeacon(netdev)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting AP beacon");
		retval = FAIL;
	}
	disableAmpduTxAll(vmacSta_p);

	{
		struct wlprivate *wlp =
			NETDEV_PRIV_P(struct wlprivate,
				      wlpptr->wlpd_p->rootdev);
		struct net_device *vdev;
		int i;

		for (i = 0; i < MAX_VMAC_INSTANCE_AP + 2; i++) {
			vdev = wlp->vdev[i];

			if (wlFwSetApMode(vdev, *(mib->mib_ApMode))) {
				WLDBG_EXIT_INFO(DBG_LEVEL_0, "setting AP MODE");
				retval = FAIL;
			}
		}
	}

#ifndef SOC_W906X
	if (wlFwSetAPBss(netdev, WL_ENABLE)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling AP bss");
		retval = FAIL;
	}
#endif
	if (wlFwSetSpectrumMgmt
	    (netdev, mib_SpectrumMagament_p->spectrumManagement)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling spectrum management");
		retval = FAIL;
	}
	/* power constraint ino IE should appear in beacon only on 5GHz */
	if (((mib_SpectrumMagament_p->spectrumManagement) &&
	     (Is5GBand(*(mib->mib_ApMode)) ||
	      (*(mib->mib_ApMode) == AP_MODE_N_ONLY)))
#ifdef IEEE80211K
	    || *(mib->mib_rrm)
#endif
		) {
		if (wlFwSetPowerConstraint
		    (netdev, mib_SpectrumMagament_p->powerConstraint)) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "setting power constraint info element");
			retval = FAIL;
		}
	}

	if (mib_SpectrumMagament_p->multiDomainCapability
#ifdef IEEE80211K
	    || *(mib->mib_rrm)
#endif
		) {
		if (wlFwSetCountryCode
		    (netdev, mib_SpectrumMagament_p->countryCode)) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "setting country code info element");
			retval = FAIL;
		}
	} else {
		/* remove the country code element from beacon */
		if (wlFwSetCountryCode(netdev, 0)) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "setting country code info element");
			retval = FAIL;
		}
	}
#ifndef SOC_W906X
	if ((*(mib->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) ||
	    AnyDevAmsduEnabled(wlpptr->master)) {
		if (wlFwSetFwFlushTimer(netdev, *(mib->mib_amsdu_flushtime))) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0,
					"setting Fw Flush timer failed");
			retval = FAIL;
		}
	} else {
		if (wlFwSetFwFlushTimer(netdev, 0)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0,
					"setting Fw Flush timer failed");
			retval = FAIL;
		}
	}
#endif

#ifdef MRVL_WSC
	combIE = wl_kmalloc(sizeof(WSC_COMB_IE_t), GFP_ATOMIC);
	if (combIE == NULL) {
		printk("No memory left for WPS IE\n");
		retval = FAIL;
	} else {
		memset(combIE, 0, sizeof(WSC_COMB_IE_t));
		if (vmacSta_p->thisbeaconIEs.Len != 0) {
			memcpy(&combIE->beaconIE, &vmacSta_p->thisbeaconIEs,
			       sizeof(WSC_BeaconIEs_t));
			if (wlFwSetWscIE(netdev, 0, combIE)) {
				WLDBG_WARNING(DBG_LEVEL_1,
					      "Setting Beacon WSC IE");
				retval = FAIL;
			}
		}
		if (vmacSta_p->thisprobeRespIEs.Len != 0) {
			memcpy(&combIE->probeRespIE,
			       &vmacSta_p->thisprobeRespIEs,
			       sizeof(WSC_ProbeRespIEs_t));
			if (wlFwSetWscIE(netdev, 1, combIE)) {
				WLDBG_WARNING(DBG_LEVEL_1,
					      "Setting Probe Response WSC IE");
				retval = FAIL;
			}
		}
		wl_kfree(combIE);
	}
#endif

#ifdef SOC_W906X
	if (wlFwSetAPBss(netdev, WL_ENABLE)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling AP bss");
		retval = FAIL;
	}
#endif

	SendResetCmd(wlpptr->vmacSta_p, 0);
#ifdef WDS_FEATURE
	// WDS ports must be initialized here since WDS ports are added to station
	// database after Mac reset and initialization.
	AP_InitWdsPorts(wlpptr);
#ifndef SOC_W906X
	wlFwSetWdsMode(netdev);
#endif
#endif
	if (*(mib->mib_rifsQNum) != 0)
		if (wlFwSetRifs(netdev, *(mib->mib_rifsQNum))) {
			WLDBG_WARNING(DBG_LEVEL_1, "set RIFS");
			retval = FAIL;
		}
#ifdef SOC_W906X
	wlFwSetSecurityKey(netdev, ACT_DEL, 0, vmacSta_p->macStaAddr, 0, 0, 0,
			   NULL);
#else
	keyMgmtCleanGroupKey(netdev);
	wlFwSetNewStn(netdev, vmacSta_p->macStaAddr, 0, 0, 0, NULL, 0, 0, 0);	//add new station
#endif
	wlFwSetSecurity(netdev, vmacSta_p->macStaAddr);

	if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled) {
		KeyMgmtInit(vmacSta_p);
	}
#ifdef MRVL_WAPI
	{
		UINT32 *pDW = (UINT32 *) vmacSta_p->wapiPN;
		*pDW++ = 0x5c365c37;
		*pDW++ = 0x5c365c36;
		*pDW++ = 0x5c365c36;
		*pDW = 0x5c365c36;
		pDW = (UINT32 *) vmacSta_p->wapiPN_mc;
		*pDW++ = 0x5c365c36;
		*pDW++ = 0x5c365c36;
		*pDW++ = 0x5c365c36;
		*pDW = 0x5c365c36;
	}
#endif
	/* reset HtOpMode, inform both driver and f/w */
	wlpptr->wlpd_p->BcnAddHtOpMode = 0;
	wlFwSetNProtOpMode(netdev, 0);
#ifdef WTP_SUPPORT
	wlFwSetWtpMode(netdev);
#endif

#ifdef CONFIG_MC_BC_RATE
	if (*(mib->mib_mcDataRateInfo)) {
		wlFwNewDP_RateDrop(netdev, 7, *(mib->mib_mcDataRateInfo), 0);
	}
	if (*(mib->mib_bcDataRateInfo)) {
		wlFwNewDP_RateDrop(netdev, 8, *(mib->mib_bcDataRateInfo), 0);
	}
#endif

	/*Call this at the end after wlFwSetAPBss . In wdev0ap0 mode, wlFwMultiBssApplySettings is called last */
	SendBFMRconfig(netdev);
	return SUCCESS;
}

#ifdef CLIENT_SUPPORT
int
wlFwApplyClientSettings(struct net_device *netdev)
{
	int retval = SUCCESS;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	mib_Update();
#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return retval;
	}
#endif

#ifndef SOC_W906X
	if (wlFwSetInfraMode(netdev)) {
		WLDBG_WARNING(DBG_LEVEL_0, "enabling Sta mode");
		retval = FAIL;
	}
#endif

#ifdef SOC_W906X
	if (wlFwSetIEs(netdev)) {
		WLDBG_WARNING(DBG_LEVEL_0, "setting IEs");
		retval = FAIL;
	}

	{
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

		if (wlFwSetRTSThreshold(netdev, *(mib->mib_RtsThresh))) {
			WLDBG_WARNING(DBG_LEVEL_0, "setting rts threshold");
			retval = FAIL;
		}
	}
#endif

	/*Call this at the end after wlFwSetAPBss . In wdev0sta0 mode, wlFwApplyClientSettings is called last */
	SendBFMRconfig(netdev);
	return SUCCESS;
}
#endif
int
wlFwGetAddrValue(struct net_device *netdev, UINT32 addr, UINT32 startIdx,
		 UINT32 * val, UINT16 set)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_MEM_ADDR_ACCESS *pCmd =
		(HostCmd_DS_MEM_ADDR_ACCESS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	UINT32 *dst = NULL;
	dma_addr_t dst_phys_addr;
	UINT32 dst_phys_addr_low;

	if (!val)
		return retval;
	WLDBG_ENTER(DBG_LEVEL_1);

	if (set == 3) {
		dst = wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
					    startIdx * sizeof(u32),
					    &dst_phys_addr,
					    wlpptr->wlpd_p->dma_alloc_flags);
		if (!dst)
			return retval;

		dst_phys_addr_low = (u32) dst_phys_addr;
	}

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_MEM_ADDR_ACCESS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_MEM_ADDR_ACCESS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_MEM_ADDR_ACCESS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Address = ENDIAN_SWAP32(addr);
	pCmd->Length = ENDIAN_SWAP16(startIdx);
	if (set == 3) {
		pCmd->Value[0] = ENDIAN_SWAP32(dst_phys_addr_low);
		pCmd->Value[1] = ENDIAN_SWAP32(startIdx);	/* data length (size of u32) */
	} else
		pCmd->Value[0] = ENDIAN_SWAP32(*val);
	pCmd->Reserved = ENDIAN_SWAP16(set);
	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_DS_MEM_ADDR_ACCESS));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_MEM_ADDR_ACCESS);
	if (!retval) {
		if (set == 3) {
			memcpy((void *)val, (void *)dst,
			       startIdx * sizeof(u32));
			wl_dma_free_coherent(wlpptr->wlpd_p->dev,
					     startIdx * sizeof(u32), dst,
					     dst_phys_addr);
		} else
			memcpy((void *)val, (void *)pCmd->Value,
			       sizeof(pCmd->Value));
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlRegMac(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_MAC_REG_ACCESS *pCmd =
		(HostCmd_DS_MAC_REG_ACCESS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_MAC_REG_ACCESS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_MAC_REG_ACCESS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_MAC_REG_ACCESS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Offset = ENDIAN_SWAP16(reg);
	pCmd->Action = ENDIAN_SWAP16(flag);
	pCmd->Value = ENDIAN_SWAP32(*val);
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_MAC_REG_ACCESS));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_MAC_REG_ACCESS);
	if (!retval)
		*val = ENDIAN_SWAP32(pCmd->Value);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlRegRF(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_RF_REG_ACCESS *pCmd =
		(HostCmd_DS_RF_REG_ACCESS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_MAC_REG_ACCESS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_RF_REG_ACCESS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_RF_REG_ACCESS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Offset = ENDIAN_SWAP16(reg);
	pCmd->Action = ENDIAN_SWAP16(flag);
	pCmd->Value = *val;
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_RF_REG_ACCESS));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_RF_REG_ACCESS);
	if (!retval)
		*val = pCmd->Value;
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlRegBB(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_BBP_REG_ACCESS *pCmd =
		(HostCmd_DS_BBP_REG_ACCESS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_BBP_REG_ACCESS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_BBP_REG_ACCESS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_BBP_REG_ACCESS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Offset = ENDIAN_SWAP16(reg);
	pCmd->Action = ENDIAN_SWAP16(flag);
	pCmd->Value = *val;
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_BBP_REG_ACCESS));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_BBP_REG_ACCESS);
	if (!retval)
		*val = pCmd->Value;
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlRegCAU(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DS_BBP_REG_ACCESS *pCmd =
		(HostCmd_DS_BBP_REG_ACCESS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_BBP_REG_ACCESS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_CAU_REG_ACCESS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DS_BBP_REG_ACCESS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Offset = ENDIAN_SWAP16(reg);
	pCmd->Action = ENDIAN_SWAP16(flag);
	pCmd->Value = *val;
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_DS_BBP_REG_ACCESS));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_CAU_REG_ACCESS);
	if (!retval)
		*val = pCmd->Value;
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifndef SOC_W906X
UINT32
PciReadMacReg(struct net_device * netdev, UINT32 offset)
{
	UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_ATOMIC);
	UINT32 val;
	if (addr_val) {
		memset((void *)addr_val, 0x00, 64 * sizeof(UINT32));
		wlFwGetAddrValue(netdev, 0x8000a000 + offset, 4, addr_val, 0);
		val = addr_val[0];
		wl_kfree(addr_val);
		return val;
	}
	return 0;
}

void
PciWriteMacReg(struct net_device *netdev, UINT32 offset, UINT32 val)
{
	UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_ATOMIC);
	if (addr_val) {
		memset((void *)addr_val, 0x00, 64 * sizeof(UINT32));
		addr_val[0] = val;
		wlFwGetAddrValue(netdev, 0x8000a000 + offset, 4, addr_val, 1);
		wl_kfree(addr_val);
	}
}

static int
wlFwSetMaxTxPwr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int reduceVal = 0;
	int i;
	UINT16 maxtxpow[TX_POWER_LEVEL_TOTAL];
	UINT16 tmp;
	UINT16 chAutoWidth = ((mib->PhyDSSSTable->Chanflag.FreqBand ==
			       FREQ_BAND_2DOT4GHZ) ? CH_40_MHz_WIDTH :
			      CH_80_MHz_WIDTH);

#ifdef PWRFRAC
	switch (*(mib->mib_TxPwrFraction)) {
	case 0:
		reduceVal = 0;	/* Max */
		break;
	case 1:
		reduceVal = 2;	/* 75% -1.25db */
		break;
	case 2:
		reduceVal = 3;	/* 50% -3db */
		break;
	case 3:
		reduceVal = 6;	/* 25% -6db */
		break;

	default:
		reduceVal = *(mib->mib_MaxTxPwr);	/* larger than case 3,  pCmd->MaxPowerLevel is min */
		break;
	}
#endif
	if ((mib->PhyDSSSTable->powinited & 2) == 0) {
		wlFwGettxpower(netdev, mib->PhyDSSSTable->maxTxPow,
			       mib->PhyDSSSTable->CurrChan,
			       mib->PhyDSSSTable->Chanflag.FreqBand,
			       ((mib->PhyDSSSTable->Chanflag.ChnlWidth ==
				 CH_AUTO_WIDTH) ? chAutoWidth : mib->
				PhyDSSSTable->Chanflag.ChnlWidth),
			       mib->PhyDSSSTable->Chanflag.ExtChnlOffset);
		mib->PhyDSSSTable->powinited |= 2;
	}
	if ((mib->PhyDSSSTable->powinited & 1) == 0) {
		wlFwGettxpower(netdev, mib->PhyDSSSTable->targetPowers,
			       mib->PhyDSSSTable->CurrChan,
			       mib->PhyDSSSTable->Chanflag.FreqBand,
			       ((mib->PhyDSSSTable->Chanflag.ChnlWidth ==
				 CH_AUTO_WIDTH) ? chAutoWidth : mib->
				PhyDSSSTable->Chanflag.ChnlWidth),
			       mib->PhyDSSSTable->Chanflag.ExtChnlOffset);
		mib->PhyDSSSTable->powinited |= 1;
	}
	for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
		if (mib->PhyDSSSTable->targetPowers[i] >
		    mib->PhyDSSSTable->maxTxPow[i])
			tmp = mib->PhyDSSSTable->maxTxPow[i];
		else
			tmp = mib->PhyDSSSTable->targetPowers[i];
		maxtxpow[i] = ((tmp - reduceVal) > 0) ? (tmp - reduceVal) : 0;
	}
	return wlFwSettxpowers(netdev, maxtxpow, HostCmd_ACT_GEN_SET,
			       mib->PhyDSSSTable->CurrChan,
			       mib->PhyDSSSTable->Chanflag.FreqBand,
			       mib->PhyDSSSTable->Chanflag.ChnlWidth,
			       mib->PhyDSSSTable->Chanflag.ExtChnlOffset);
}
#endif /* #ifndef SOC_W906X */

static int
wlFwSetAdaptMode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	HostCmd_DS_SET_RATE_ADAPT_MODE *pCmd =
		(HostCmd_DS_SET_RATE_ADAPT_MODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_SET_RATE_ADAPT_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RATE_ADAPT_MODE);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_SET_RATE_ADAPT_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->RateAdaptMode = ENDIAN_SWAP16(*(mib->mib_RateAdaptMode));
	pCmd->Action = ENDIAN_SWAP16(HostCmd_ACT_GEN_SET);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RATE_ADAPT_MODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifndef SOC_W906X
static int
wlFwSetCSAdaptMode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	HostCmd_DS_SET_LINKADAPT_CS_MODE *pCmd =
		(HostCmd_DS_SET_LINKADAPT_CS_MODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DS_SET_LINKADAPT_CS_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_LINKADAPT_CS_MODE);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_DS_SET_LINKADAPT_CS_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ) {
		*(mib->mib_CSMode) = LINKADAPT_CS_ADAPT_STATE_AUTO_ENABLED;
	} else {
		*(mib->mib_CSMode) = LINKADAPT_CS_ADAPT_STATE_CONSERV;
	}
	pCmd->CSMode = ENDIAN_SWAP16(*(mib->mib_CSMode));
	pCmd->Action = ENDIAN_SWAP16(HostCmd_ACT_GEN_SET);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_LINKADAPT_CS_MODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif /* #ifndef SOC_W906X */

#ifdef WDS_FEATURE
int
wlFwSetWdsMode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//      vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	HostCmd_WDS *pCmd = (HostCmd_WDS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;

	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_0);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_WDS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_WDS_ENABLE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_WDS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->WdsEnable =
		ENDIAN_SWAP32(*(wlpptr->vmacSta_p->Mib802dot11->mib_wdsEnable));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_WDS_ENABLE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif
static int
wlFwSetNProt(struct net_device *netdev, UINT32 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_N_PROTECT_FLAG *pCmd =
		(HostCmd_FW_SET_N_PROTECT_FLAG *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "N prot mode %d", mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_N_PROTECT_FLAG));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_N_PROTECT_FLAG);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_N_PROTECT_FLAG));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->NProtectFlag = ENDIAN_SWAP32(mode);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_N_PROTECT_FLAG));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_N_PROTECT_FLAG);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetNProtOpMode(struct net_device *netdev, UINT8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_N_PROTECT_OPMODE *pCmd =
		(HostCmd_FW_SET_N_PROTECT_OPMODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "N prot OP mode %d", mode);
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_N_PROTECT_OPMODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_N_PROTECT_OPMODE);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_N_PROTECT_OPMODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->NProtectOpMode = mode;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_N_PROTECT_OPMODE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_N_PROTECT_OPMODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifndef SOC_W906X
static int
wlFwSetOptimizationLevel(struct net_device *netdev, UINT8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_OPTIMIZATION_LEVEL *pCmd =
		(HostCmd_FW_SET_OPTIMIZATION_LEVEL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Optimization %d", mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_OPTIMIZATION_LEVEL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_OPTIMIZATION_LEVEL);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_OPTIMIZATION_LEVEL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->OptLevel = mode;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_OPTIMIZATION_LEVEL));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_OPTIMIZATION_LEVEL);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif /* #ifndef SOC_W906X */

#ifdef SOC_W906X
int
wlFwSetAcntStop(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_ACNT_STOP *pCmd =
		(HostCmd_FW_SET_ACNT_STOP *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_ACNT_STOP));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_ACNT_STOP);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_ACNT_STOP));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_ACNT_STOP));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_ACNT_STOP);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif /* #ifndef SOC_W906X */

int
wlFwGetCalTable(struct net_device *netdev, UINT8 annex, UINT8 index)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	HostCmd_FW_GET_CALTABLE *pCmd =
		(HostCmd_FW_GET_CALTABLE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	//WLDBG_ENTER_INFO(DBG_LEVEL_1, "Optimization %d", mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_CALTABLE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_CALTABLE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_CALTABLE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->annex = annex;
	pCmd->index = index;

	memset(&wlpptr->calTbl, 0x00, CAL_TBL_SIZE);

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_FW_GET_CALTABLE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_CALTABLE);
	if (!retval)
		memcpy(&wlpptr->calTbl, &pCmd->calTbl, CAL_TBL_SIZE);

	if ((wlpptr->calTbl[0] != annex) && (annex != 0) && (annex != 255))
		retval = FAIL;

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetMimoPsHt(struct net_device *netdev, UINT8 * addr, UINT8 enable,
		UINT8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	HostCmd_FW_SET_MIMOPSHT *pCmd =
		(HostCmd_FW_SET_MIMOPSHT *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_MIMOPSHT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MIMOPSHT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_MIMOPSHT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	memcpy(pCmd->Addr, addr, 6);
	pCmd->Enable = enable;
	pCmd->Mode = mode;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_MIMOPSHT));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_MIMOPSHT);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetSecurity(struct net_device *netdev, u_int8_t * staaddr)
{
	int retval = SUCCESS;

	if (wlFwSetWep(netdev, staaddr)) {
		printk("setting wep keyto sta fail\n");
		retval = FAIL;
	}
	return retval;
}

#ifndef SOC_W906X
static int
wlFwGetPwrCalTable(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *syscfg = (vmacApInfo_t *) wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = syscfg->Mib802dot11;
	MIB_802DOT11 *mib1 = syscfg->ShadowMib802dot11;
	UINT16 len;

	if (syscfg->txPwrTblLoaded) {
		return SUCCESS;
	}
	syscfg->txPwrTblLoaded = 1;

	if (wlFwGetCalTable(netdev, 33, 0) != FAIL) {
		len = wlpptr->calTbl[2] | (wlpptr->calTbl[3] << 8);
		len -= 12;
		if (len > PWTAGETRATETABLE20M)
			len = PWTAGETRATETABLE20M;
		memcpy(mib->PowerTagetRateTable20M, &wlpptr->calTbl[12], len);
		memcpy(mib1->PowerTagetRateTable20M, &wlpptr->calTbl[12], len);
	}

	if (wlFwGetCalTable(netdev, 34, 0) != FAIL) {
		len = wlpptr->calTbl[2] | (wlpptr->calTbl[3] << 8);
		len -= 12;
		if (len > PWTAGETRATETABLE40M)
			len = PWTAGETRATETABLE40M;
		memcpy(mib->PowerTagetRateTable40M, &wlpptr->calTbl[12], len);
		memcpy(mib1->PowerTagetRateTable40M, &wlpptr->calTbl[12], len);
	}

	if (wlFwGetCalTable(netdev, 35, 0) != FAIL) {
		len = wlpptr->calTbl[2] | (wlpptr->calTbl[3] << 8);
		len -= 20;
		if (len > PWTAGETRATETABLE20M_5G)
			len = PWTAGETRATETABLE20M_5G;
		memcpy(mib->PowerTagetRateTable20M_5G, &wlpptr->calTbl[20],
		       len);
		memcpy(mib1->PowerTagetRateTable20M_5G, &wlpptr->calTbl[20],
		       len);
	}

	if (wlFwGetCalTable(netdev, 36, 0) != FAIL) {
		len = wlpptr->calTbl[2] | (wlpptr->calTbl[3] << 8);
		len -= 20;
		if (len > PWTAGETRATETABLE40M_5G)
			len = PWTAGETRATETABLE40M_5G;
		memcpy(mib->PowerTagetRateTable40M_5G, &wlpptr->calTbl[20],
		       len);
		memcpy(mib1->PowerTagetRateTable40M_5G, &wlpptr->calTbl[20],
		       len);

	}
	return SUCCESS;
}

int
wlFwGet_Device_Region_Code(struct net_device *netdev,
			   UINT32 * EEPROM_Region_Code)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_GET_REGION_CODE *pCmd =
		(HostCmd_FW_GET_REGION_CODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	u32 status;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_REGION_CODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_FW_REGION_CODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_REGION_CODE));
	pCmd->status = ENDIAN_SWAP16(HostCmd_CMD_GET_FW_REGION_CODE);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_FW_REGION_CODE);
	if (pCmd->status != 0) {
#ifndef OPENWRT
		printk("Unable to Get Device Region Code\n");
#endif
	} else {
		*EEPROM_Region_Code = pCmd->FW_Region_Code;
#ifndef OPENWRT
		printk("Device Region Code is: 0x%x \n",
		       (u_int32_t) pCmd->FW_Region_Code);
#endif
	}

	status = pCmd->status;
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	if (retval != SUCCESS)	// Non 0 is not success
		return retval;
	else
		return status;
}

int
wlFwGet_Device_PwrTbl(struct net_device *netdev,
		      channel_power_tbl_t * EEPROM_CH_PwrTbl,
		      UINT8 * region_code, UINT8 * number_of_channels,
		      UINT32 channel_index)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_GET_EEPROM_PWR_TBL *pCmd =
		(HostCmd_FW_GET_EEPROM_PWR_TBL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	u32 status;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_EEPROM_PWR_TBL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HOSTCMD_CMD_GET_DEVICE_PWR_TBL);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_EEPROM_PWR_TBL));
	pCmd->status = ENDIAN_SWAP16(HOSTCMD_CMD_GET_DEVICE_PWR_TBL);
	pCmd->current_channel_index = channel_index;

	retval = wlexecuteCommand(netdev, HOSTCMD_CMD_GET_DEVICE_PWR_TBL);
	memcpy(EEPROM_CH_PwrTbl, &pCmd->channelPwrTbl,
	       sizeof(channel_power_tbl_t));
	*region_code = pCmd->region_code;
	*number_of_channels = pCmd->number_of_channels;

	status = pCmd->status;
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	if (retval != SUCCESS)	// Non 0 is not success
		return retval;
	else
		return status;
}

static int
wlFwGetRegionCode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *syscfg = (vmacApInfo_t *) wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = syscfg->Mib802dot11;
	MIB_802DOT11 *mib1 = syscfg->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament1_p = mib1->SpectrumMagament;
	UINT32 Device_Region_Code;

	if (syscfg->regionCodeLoaded) {
		return SUCCESS;
	}
	syscfg->regionCodeLoaded = 1;

	if (wlFwGet_Device_Region_Code(netdev, &Device_Region_Code) != FAIL) {
		printk("Using Device Region Code!\n");
		mib_SpectrumMagament_p->countryCode = Device_Region_Code;
		mib_SpectrumMagament1_p->countryCode = Device_Region_Code;
		*(mib->mib_regionCode) = Device_Region_Code;
		*(mib1->mib_regionCode) = Device_Region_Code;
		domainSetDomain(mib_SpectrumMagament1_p->countryCode);
	} else if (wlFwGetCalTable(netdev, 0, 0) != FAIL) {
		printk("Using External Region Code!\n");
		/* if this line is not added, the user configured region code will be overwritten by regioncode read from fw */
		if (!bcn_reg_domain) {
			mib_SpectrumMagament_p->countryCode =
				wlpptr->calTbl[16];
			mib_SpectrumMagament1_p->countryCode =
				wlpptr->calTbl[16];
			domainSetDomain(mib_SpectrumMagament1_p->countryCode);
		}
	}
	//printk("code 0x%x\n", mib_SpectrumMagament_p->countryCode ); 
	return SUCCESS;
}
#endif /*#ifndef SOC_W906X */

#ifdef SOC_W906X
#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
int
wlFwGet_EEPROM_Region_Code(struct net_device *netdev,
			   UINT32 * EEPROM_Region_Code)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_GET_REGION_CODE *pCmd =
		(HostCmd_FW_GET_REGION_CODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_REGION_CODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_FW_REGION_CODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_REGION_CODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_FW_REGION_CODE);
	*EEPROM_Region_Code = pCmd->FW_Region_Code;
	printk("EEPROM Region Code is: 0x%x \n",
	       (u_int32_t) pCmd->FW_Region_Code);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwGet_EEPROM_PwrTbl(struct net_device *netdev,
		      channel_power_tbl_t * EEPROM_CH_PwrTbl,
		      UINT8 * region_code, UINT8 * number_of_channels,
		      UINT32 channel_index)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_GET_EEPROM_PWR_TBL *pCmd =
		(HostCmd_FW_GET_EEPROM_PWR_TBL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
	u32 status;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_EEPROM_PWR_TBL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_EEPROM_PWR_TBL);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_EEPROM_PWR_TBL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->status = ENDIAN_SWAP16(HostCmd_CMD_GET_EEPROM_PWR_TBL);
	pCmd->current_channel_index = channel_index;

	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_EEPROM_PWR_TBL);
	memcpy(EEPROM_CH_PwrTbl, &pCmd->channelPwrTbl,
	       sizeof(channel_power_tbl_t));
	*region_code = pCmd->region_code;
	*number_of_channels = pCmd->number_of_channels;

	status = pCmd->status;
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	if (retval != SUCCESS)	// Non 0 is not success
		return retval;
	else
		return status;
}
#endif

static int
wlFwGetRegionCode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *syscfg = (vmacApInfo_t *) wlpptr->vmacSta_p;
#if 0				/* TODO: Enable after FW support this command. */
	MIB_802DOT11 *mib = syscfg->Mib802dot11;
	MIB_802DOT11 *mib1 = syscfg->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament1_p = mib1->SpectrumMagament;
#endif //0

#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
	UINT32 EEPROM_Region_Code;
#endif

	if (syscfg->regionCodeLoaded) {
		return SUCCESS;
	}
	syscfg->regionCodeLoaded = 1;

#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
	if (wlFwGet_EEPROM_Region_Code(netdev, &EEPROM_Region_Code) != FAIL) {
		mib_SpectrumMagament_p->countryCode = EEPROM_Region_Code;
		mib_SpectrumMagament1_p->countryCode = EEPROM_Region_Code;
		*(mib->mib_regionCode) = EEPROM_Region_Code;
		*(mib1->mib_regionCode) = EEPROM_Region_Code;
		domainSetDomain(mib_SpectrumMagament1_p->countryCode);
	}
#else
#if 0				/* TODO: Enable after FW support this command. */
	if (wlFwGetCalTable(netdev, 0, 0) != FAIL) {
		/* if this line is not added, the user configured region code will be overwritten by regioncode read from fw */
		if (!bcn_reg_domain) {
			mib_SpectrumMagament_p->countryCode =
				wlpptr->calTbl[16];
			mib_SpectrumMagament1_p->countryCode =
				wlpptr->calTbl[16];
			domainSetDomain(mib_SpectrumMagament1_p->countryCode);
		}
	}
#endif
#endif
	//printk("code 0x%x\n", mib_SpectrumMagament_p->countryCode );
	return SUCCESS;
}
#endif /* #ifdef SOC_W906X */

int
wlFwGetBeacon(struct net_device *netdev, UINT8 * pBcn, UINT16 * pLen)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_GET_BEACON *pCmd =
		(HostCmd_FW_GET_BEACON *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	//WLDBG_ENTER_INFO(DBG_LEVEL_1, "Optimization %d", mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_BEACON));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_BEACON);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_BEACON));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
	pCmd->Bcnlen = 0;

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_FW_GET_BEACON));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_BEACON);
	if (!retval) {
		memcpy(pBcn, &pCmd->Bcn, pCmd->Bcnlen);
		*pLen = pCmd->Bcnlen;
	}
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetRifs(struct net_device *netdev, UINT8 QNum)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_RIFS *pCmd =
		(HostCmd_FW_SET_RIFS *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_CMD_SET_RIFS));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RIFS);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_RIFS));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->QNum = QNum;

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RIFS);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetHTGF(struct net_device *netdev, UINT32 mode)
{
#ifndef SOC_W906X
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_HT_GF_MODE *pCmd =
		(HostCmd_FW_HT_GF_MODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_HT_GF_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_HT_GF_MODE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_HT_GF_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP32(WL_SET);
	pCmd->Mode = ENDIAN_SWAP32(mode);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_HT_GF_MODE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
#else
	return SUCCESS;
#endif /* #ifndef SOC_W906X */
}

int
wlFwSetHTStbc(struct net_device *netdev, UINT32 mode)
{
	int retval = FAIL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_HT_STBC_MODE *pCmd =
		(HostCmd_FW_HT_STBC_MODE *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_HT_STBC_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_HT_TX_STBC);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_HT_STBC_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP32(WL_SET);
	pCmd->Mode = ENDIAN_SWAP32(mode);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_HT_TX_STBC);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef SOC_W906X
int
wlFwGetRateTable(struct net_device *netdev, UINT8 * addr, UINT8 * pRateInfo,
		 UINT32 size, UINT8 type, UINT16 staid)
#else
int
wlFwGetRateTable(struct net_device *netdev, UINT8 * addr, UINT8 * pRateInfo,
		 UINT32 size, UINT8 type)
#endif
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	HostCmd_FW_GET_RATETABLE *pCmd =
		(HostCmd_FW_GET_RATETABLE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
#ifdef SOC_W906X
	extStaDb_StaInfo_t *pStaInfo;
	UINT16 index;

	if ((pStaInfo =
	     extStaDb_GetStaInfo(wlpptr->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) addr,
				 STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
		//return retval;
		index = staid;
	} else {
		index = pStaInfo->StnId;
	}
#endif

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_RATETABLE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_RATETABLE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_RATETABLE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Type = type;
#ifdef SOC_W906X
	pCmd->staid = index;
#else
	memcpy(pCmd->Addr, addr, 6);
#endif

	memset(pRateInfo, 0x00, size);

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_FW_GET_RATETABLE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_RATETABLE);

	if (!retval)
		memcpy(pRateInfo, &pCmd->SortedRatesIndexMap, size);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

/*Function to set custom rate in rate table
 * INPUTS:
 * action: 0:Clear existing rate table, 1: add custom rateinfo
 * addr: client mac addr
 * rateinfo: 32 bit rateinfo to be added into rate table
 */
#ifdef SOC_W906X
int
wlFwSetRateTable(struct net_device *netdev, UINT32 action, UINT8 * addr,
		 UINT16 staid, UINT32 rateinfo)
#else
int
wlFwSetRateTable(struct net_device *netdev, UINT32 action, UINT8 * addr,
		 UINT32 rateinfo)
#endif
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	HostCmd_FW_SET_RATETABLE *pCmd =
		(HostCmd_FW_SET_RATETABLE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;
#ifdef SOC_W906X
	extStaDb_StaInfo_t *pStaInfo;
	UINT16 index;

	if ((pStaInfo =
	     extStaDb_GetStaInfo(wlpptr->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) addr,
				 STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
		//return retval;
		index = staid;
	} else
		index = pStaInfo->StnId;
#endif

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_RATETABLE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RATETABLE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_RATETABLE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP32(action);
	pCmd->Rateinfo = ENDIAN_SWAP32(rateinfo);
#ifdef SOC_W906X
	pCmd->staid = index;
#else
	memcpy(pCmd->Addr, addr, 6);
#endif

	WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
			sizeof(HostCmd_FW_SET_RATETABLE));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RATETABLE);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef MFG_SUPPORT
typedef PACK_START struct mfg_CmdRfReg_t {
	UINT32 mfgCmd;
	UINT32 Action;
	UINT32 Error;
	UINT32 Address;
	UINT32 Data;
	UINT32 deviceId;
} PACK_END mfg_CmdRfReg_t;

int
wlFwMfgCmdIssue(struct net_device *netdev, char *pData, char *pDataOut)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	FWCmdHdr *pCmd = (FWCmdHdr *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	UINT8 *p = pData + 2;
	UINT16 CmdLen = ENDIAN_SWAP16(*(UINT16 *) p);
	ktime_t start_time;

	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, CmdLen);

	memcpy((void *)pCmd, (void *)pData, CmdLen);

	WLDBG_INFO(DBG_LEVEL_0, "MFG Command to FW");
	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, CmdLen);

	start_time = ktime_get_real();
	retval = wlexecuteCommand(netdev, HostCmd_CMD_MFG_COMMAND);

	if (!retval) {
		s64 time_elapsed =
			ktime_to_us(ktime_sub(ktime_get_real(), start_time));
		UINT8 *p_r = (UINT8 *) pCmd + 2;
		UINT16 CmdLen_r = ENDIAN_SWAP16(*(UINT16 *) p_r);

		memcpy((void *)pDataOut, (void *)pCmd, CmdLen_r);
		WLDBG_INFO(DBG_LEVEL_0, "Result from FW, time elapsed %lld us",
			   time_elapsed);
		netdev_notice(netdev, "time elapsed %lld us", time_elapsed);
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pDataOut, CmdLen_r);
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

	return retval;
}
#endif

#ifdef MRVL_DFS
#define DFS_DISABLED    0
#define DFS_ENABLED     1

extern UINT16 getCacTimerValue(UINT16 regionCode, UINT16 cacTimeout,
			       UINT16 etsiTimeout, CHNL_FLAGS * pChanflag,
			       UINT8 channel, UINT8 channel2);
int
DecideDFSOperation(struct net_device *netdev, BOOLEAN bChannelChanged,
		   BOOLEAN bBandWidthChanged, UINT8 currDFSState,
		   UINT8 newDFSState, MIB_802DOT11 * mib)
{
	UINT8 noChannelChangeCheck = 0;
	smeQ_MgmtMsg_t *toSmeMsg = NULL;
	UINT32 action = 0;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT16 mib_CACTimeOut = 0;
	UINT8 chan = mib->PhyDSSSTable->CurrChan;
	UINT8 chan2 = mib->PhyDSSSTable->SecChan;
	CHNL_FLAGS *pChanflag = &mib->PhyDSSSTable->Chanflag;

	/* First check if DFS is instantiated or not */
	if (wlpptr->wlpd_p->pdfsApMain) {
		if (currDFSState == DFS_DISABLED) {
			/* This scenario cannot occur. */
			DfsDeInit(wlpptr->wlpd_p);
			return SUCCESS;
		} else {	/*currDFSState = 1 */
			if (newDFSState == DFS_DISABLED) {
				DfsDeInit(wlpptr->wlpd_p);
				return SUCCESS;
			}
		}
	} else {
		if (currDFSState == DFS_DISABLED) {
			if (newDFSState == DFS_ENABLED) {
				DfsInit(netdev, wlpptr->wlpd_p);
				noChannelChangeCheck = 1;
			} else {
				/* Do not enter into DFS SM */
				return SUCCESS;
			}
		} else {
			if (newDFSState == DFS_ENABLED) {
				/* This can happen when the AP boots up first time and
				   driver deafult is DFS Enabled
				 */
				DfsInit(netdev, wlpptr->wlpd_p);
				noChannelChangeCheck = 1;
			} else {
				/* Do not enter into DFS SM */
				return SUCCESS;
			}
		}
	}
	if (wlpptr->wlpd_p->pdfsApMain == NULL) {
		WLDBG_INFO(DBG_LEVEL_0,
			   "DecideDFSOperation: failed to alloc DFS buffer\n");
		return FAIL;
	}
	if (*(mib->mib_NOPTimeOut) != 0) {
		DfsSetNOCTimeOut(wlpptr->wlpd_p->pdfsApMain,
				 *(mib->mib_NOPTimeOut));
	}
	mib_CACTimeOut =
		getCacTimerValue(*(mib->mib_regionCode), *(mib->mib_CACTimeOut),
				 *(mib->mib_ETSICACTimeOut), pChanflag, chan,
				 chan2);

	if (mib_CACTimeOut != 0) {
		DfsSetCACTimeOut(wlpptr->wlpd_p->pdfsApMain, mib_CACTimeOut);
	}

	if (wlpptr->wlpd_p->bCACChannelChanged) {
		bChannelChanged = TRUE;
		wlpptr->wlpd_p->bCACChannelChanged = FALSE;
	}
	if (wlpptr->wlpd_p->bCACBWChanged) {
		bBandWidthChanged = TRUE;
		wlpptr->wlpd_p->bCACBWChanged = FALSE;
	}
	if (bChannelChanged || noChannelChangeCheck || bBandWidthChanged) {

		/* Send Channel Change Event to DFS SM */
		if ((toSmeMsg =
		     (smeQ_MgmtMsg_t *) wl_kmalloc(sizeof(smeQ_MgmtMsg_t),
						   GFP_ATOMIC)) == NULL) {
			WLDBG_INFO(DBG_LEVEL_0,
				   "DecideDFSOperation: failed to alloc msg buffer\n");
			return FAIL;
		}

		memset(toSmeMsg, 0, sizeof(smeQ_MgmtMsg_t));

		toSmeMsg->MsgType = SME_NOTIFY_CHANNELSWITCH_CFRM;

		toSmeMsg->Msg.ChanSwitchCfrm.result = 1;
		toSmeMsg->Msg.ChanSwitchCfrm.chInfo.channel =
			PhyDSSSTable->CurrChan;
#ifdef SOC_W906X
		toSmeMsg->Msg.ChanSwitchCfrm.chInfo.channel2 =
			PhyDSSSTable->SecChan;
#endif
		memcpy(&toSmeMsg->Msg.ChanSwitchCfrm.chInfo.chanflag,
		       &PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));
		toSmeMsg->vmacSta_p = vmacSta_p;

		smeQ_MgmtWriteNoBlock(toSmeMsg);
		wl_kfree((UINT8 *) toSmeMsg);
	} else {
		action = DFSGetCurrentRadarDetectionMode(wlpptr->wlpd_p->
							 pdfsApMain,
							 PhyDSSSTable->CurrChan,
							 PhyDSSSTable->SecChan,
							 PhyDSSSTable->
							 Chanflag);
		wlFwSetRadarDetection(netdev, action);

	}
	return SUCCESS;
}
#endif
#ifdef WMON
UINT32
Rx_Traffic_FCS_Cnt(struct net_device * dev)
{
	return PciReadMacReg(dev, RX_TRAFFIC_ERR_CNT);
}
#endif
#ifdef RXPATHOPT
int
wlFwSetRxPathOpt(struct net_device *netdev, UINT32 rxPathOpt)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_SET_RXPATHOPT *pCmd =
		(HostCmd_SET_RXPATHOPT *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set RXPATHOPT to %d", rxPathOpt);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_SET_RXPATHOPT));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_RXPATHOPT);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_RXPATHOPT));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->RxPathOpt = ENDIAN_SWAP32(rxPathOpt);
	pCmd->RxPktThreshold = ENDIAN_SWAP32(0);	//use fw default.
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_SET_RXPATHOPT));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_RXPATHOPT);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif
#ifdef V6FW
int
wlFwSetDwdsStaMode(struct net_device *netdev, UINT32 enable)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_DWDS_ENABLE *pCmd =
		(HostCmd_DWDS_ENABLE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set DwdsStaMode to %d", enable);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_DWDS_ENABLE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_DWDS_ENABLE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DWDS_ENABLE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Enable = ENDIAN_SWAP32(enable);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(HostCmd_DWDS_ENABLE));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_DWDS_ENABLE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif

int
wlFwSetFwFlushTimer(struct net_device *netdev, UINT32 usecs)
{
#ifndef SOC_W906X
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_FLUSH_TIMER *pCmd =
		(HostCmd_FW_FLUSH_TIMER *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set FwFlushTimer to %d usecs", usecs);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_FLUSH_TIMER));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_FW_FLUSH_TIMER);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_FLUSH_TIMER));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->value = ENDIAN_SWAP32(usecs);
	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_FLUSH_TIMER));
	retval = wlexecuteCommand(netdev, HostCmd_CMD_FW_FLUSH_TIMER);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
#else
	return SUCCESS;
#endif
}

#ifdef COEXIST_20_40_SUPPORT
int
wlFwSet11N_20_40_Switch(struct net_device *netdev, UINT8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_11N_20_40_SWITCHING *pCmd =
		(HostCmd_FW_SET_11N_20_40_SWITCHING *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "20/40 switching %d", mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_11N_20_40_SWITCHING));
	pCmd->CmdHdr.Cmd =
		ENDIAN_SWAP16(HostCmd_CMD_SET_11N_20_40_CHANNEL_SWITCH);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_11N_20_40_SWITCHING));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->AddChannel = mode;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_SET_11N_20_40_SWITCHING));
	retval = wlexecuteCommand(netdev,
				  HostCmd_CMD_SET_11N_20_40_CHANNEL_SWITCH);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#endif

#ifdef EXPLICIT_BF

int
wlFwSet11N_BF_Mode(struct net_device *netdev, UINT8 bf_option,
		   UINT8 bf_csi_steering, UINT8 bf_mcsfeedback, UINT8 bf_mode,
		   UINT8 bf_interval, UINT8 bf_slp, UINT8 bf_power)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_HT_BF_MODE *pCmd =
		(HostCmd_FW_HT_BF_MODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set 11n BF mode %d %d %d %d", bf_option,
			 bf_csi_steering, bf_mcsfeedback, bf_mode);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_HT_BF_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_BF);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_HT_BF_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->option = bf_option;
	pCmd->csi_steering = bf_csi_steering;
	pCmd->mcsfeedback = bf_mcsfeedback;
	pCmd->mode = bf_mode;
	pCmd->interval = bf_interval;
	pCmd->slp = bf_slp;
	pCmd->power = bf_power;

	pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_HT_BF_MODE));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_BF);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetOfdma_Mode(struct net_device *netdev, UINT8 option, UINT8 ru_mode,
		  UINT32 max_delay, UINT8 max_sta)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_OFDMA_MODE *pCmd =
		(HostCmd_FW_OFDMA_MODE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	WLDBG_ENTER_INFO(DBG_LEVEL_0, "Set ofdma mode %d %d %d %d", option,
			 ru_mode, max_delay, max_sta);

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_HT_BF_MODE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_OFDMA);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_OFDMA_MODE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->option = option;
	pCmd->ru_mode = ru_mode;
	pCmd->max_delay = max_delay;
	pCmd->max_sta = max_sta;

	WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
			sizeof(HostCmd_FW_OFDMA_MODE));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_OFDMA);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetNoAck(struct net_device *netdev, UINT8 Enable, UINT8 be_enable,
	     UINT8 bk_enable, UINT8 vi_enable, UINT8 vo_enable)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_NOACK *pCmd =
		(HostCmd_FW_SET_NOACK *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_NOACK));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_NOACK);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_NOACK));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Enable = Enable;
	pCmd->be_enable = be_enable;
	pCmd->bk_enable = bk_enable;
	pCmd->vi_enable = vi_enable;
	pCmd->vo_enable = vo_enable;

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_NOACK);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetRCcal(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_RC_CAL *pCmd = (HostCmd_FW_RC_CAL *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_RC_CAL));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_RC_CAL);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_RC_CAL));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_RC_CAL);
	printk("RC Calibration \n");
	printk("    path A I = 0x%x Q = 0x%x \n",
	       (unsigned int)pCmd->rc_cal[0][0],
	       (unsigned int)pCmd->rc_cal[0][1]);
	printk("    path B I = 0x%x Q = 0x%x \n",
	       (unsigned int)pCmd->rc_cal[1][0],
	       (unsigned int)pCmd->rc_cal[1][1]);
	printk("    path C I = 0x%x Q = 0x%x \n",
	       (unsigned int)pCmd->rc_cal[2][0],
	       (unsigned int)pCmd->rc_cal[2][1]);
	printk("    path D I = 0x%x Q = 0x%x \n",
	       (unsigned int)pCmd->rc_cal[3][0],
	       (unsigned int)pCmd->rc_cal[3][1]);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwGetTemp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_TEMP *pCmd = (HostCmd_FW_TEMP *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_TEMP));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_TEMP);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_TEMP));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_TEMP);
	printk("Temperature = 0x%x \n", (u_int32_t) pCmd->temp);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#ifdef SOC_W906X
int
wlFwBcnGpio17Toggle(struct net_device *netdev, BOOLEAN action, u8 * enable)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_BCN_GPIO17_TOGGLE *pCmd =
		(HostCmd_FW_BCN_GPIO17_TOGGLE *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_BCN_GPIO17_TOGGLE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HOSTCMD_CMD_BCN_GPIO17_TOGGLE);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_BCN_GPIO17_TOGGLE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

	if (action) {
		pCmd->action = WL_SET;
		pCmd->enable = *enable;
	} else {
		pCmd->action = WL_GET;
	}

	retval = wlexecuteCommand(netdev, HOSTCMD_CMD_BCN_GPIO17_TOGGLE);

	if (!action) {
		*enable = pCmd->enable;
	}

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif

#ifndef SOC_W906X
int
wlFwGetPHYBW(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_PHY_BW *pCmd = (HostCmd_PHY_BW *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_PHY_BW));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_PHY_BW);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_PHY_BW));

	retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_PHY_BW);
	printk("PHY BW = %d MHz \n", (u_int32_t) pCmd->PHY_BW);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetAlphaTimingFc(struct net_device *netdev, UINT8 Enable, int Fc_Value)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_ALPHA_TIMING_FC *pCmd =
		(HostCmd_ALPHA_TIMING_FC *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_ALPHA_TIMING_FC));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HOSTCMD_CMD_SET_ALPHA_TIMING_FC);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_ALPHA_TIMING_FC));
	pCmd->Enable = Enable;
	if (Enable) {
		printk("Alpha Timing Fc Enabled with Frequency: %d MHz\n",
		       Fc_Value / 10);
		pCmd->Fc_Value = Fc_Value;
	} else {
		printk("Alpha Timing Fc Disabled\n");
	}

	retval = wlexecuteCommand(netdev, HOSTCMD_CMD_SET_ALPHA_TIMING_FC);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif

int
wlFwSetNoSteer(struct net_device *netdev, UINT8 Enable)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_NOSTEER *pCmd =
		(HostCmd_FW_SET_NOSTEER *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_NOSTEER));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_NOSTEER);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_NOSTEER));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Enable = Enable;

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_NOSTEER);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetCDD(struct net_device *netdev, UINT32 cdd_mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_SET_CDD *pCmd = (HostCmd_FW_SET_CDD *) & wlpptr->pCmdBuf[0];
	int retval = FAIL;
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_CDD));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_CDD);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_CDD));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Enable = ENDIAN_SWAP32(cdd_mode);	//U32 need swap

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_CDD);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

int
wlFwSetBFType(struct net_device *netdev, UINT32 mode)
{
	int retval = FAIL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	HostCmd_FW_HT_BF_TYPE *pCmd =
		(HostCmd_FW_HT_BF_TYPE *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable) {
		return SUCCESS;
	}
#endif
	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_HT_BF_TYPE));
	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_BFTYPE);
	pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_HT_BF_TYPE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP32(WL_SET);
	pCmd->Mode = ENDIAN_SWAP32(mode);
	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_BFTYPE);
	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}

#endif
#ifdef SSU_SUPPORT
int
wlFwSetSpectralAnalysis(struct net_device *netdev, ssu_cmd_t * pCfg)
{
	int retval = FAIL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	//UINT16 fft_len, adc_len;
	HostCmd_FW_SET_SPECTRAL_ANALYSIS_TYPE *pCmd =
		(HostCmd_FW_SET_SPECTRAL_ANALYSIS_TYPE *) & wlpptr->pCmdBuf[0];
	unsigned long flags;

	printk("wlFwSetSpectralAnalysis enter\n");

	MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
	memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_SPECTRAL_ANALYSIS_TYPE));

	pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_SPECTRAL_ANALYSIS);
	pCmd->CmdHdr.Length =
		ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_SPECTRAL_ANALYSIS_TYPE));
	pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
	pCmd->Action = ENDIAN_SWAP32(WL_SET);
	memcpy((void *)&pCmd->ssu, (void *)pCfg, sizeof(ssu_cmd_t));
//
	printk("\nSSU input params ..............\n\n");
//      printk("Cmd                = %x    \n", pCmd->CmdHdr.Cmd);
//      printk("Len                = %d    \n", pCmd->CmdHdr.Length);
//      printk("Action             = %d    \n", pCmd->Action);
	printk("Nskip              = %x    \n", pCmd->ssu.Nskip);
	printk("Nsel               = %x    \n", pCmd->ssu.Nsel);
	printk("AdcDownSample      = %x    \n", pCmd->ssu.AdcDownSample);
	printk("MaskAdcPacket      = %x    \n", pCmd->ssu.MaskAdcPacket);
	printk("Output16bits       = %x    \n", pCmd->ssu.Output16bits);
	printk("PowerEnable        = %x    \n", pCmd->ssu.PowerEnable);
	printk("RateDeduction      = %x    \n", pCmd->ssu.RateDeduction);
	printk("PacketAvg          = %x    \n", pCmd->ssu.PacketAvg);
	printk("Time               = %d    \n", pCmd->ssu.Time);
	printk("BufferBaseAddress  = 0x%08x\n", pCmd->ssu.BufferBaseAddress);
	printk("BufferBaseSize     = 0x%08x\n", pCmd->ssu.BufferBaseSize);

	retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_SPECTRAL_ANALYSIS);

	printk("\nSSU output params .............\n\n");
//      printk("Cmd                = %x    \n", pCmd->CmdHdr.Cmd);
//      printk("Len                = %d    \n", pCmd->CmdHdr.Length);
//      printk("Action             = %d    \n", pCmd->Action);
	printk("Nskip              = %d    \n", pCmd->ssu.Nskip);
	printk("Nsel               = %d    \n", pCmd->ssu.Nsel);
	printk("AdcDownSample      = %d    \n", pCmd->ssu.AdcDownSample);
	printk("MaskAdcPacket      = %d    \n", pCmd->ssu.MaskAdcPacket);
	printk("Output16bits       = %d    \n", pCmd->ssu.Output16bits);
	printk("PowerEnable        = %d    \n", pCmd->ssu.PowerEnable);
	printk("RateDeduction      = %d    \n", pCmd->ssu.RateDeduction);
	printk("PacketAvg          = %d    \n", pCmd->ssu.PacketAvg);
	printk("Time               = %d    \n", pCmd->ssu.Time);
	printk("TestMode           = %d    \n", pCmd->ssu.TestMode);
	printk("FFT_length         = %d    \n", pCmd->ssu.FFT_length);
	printk("ADC_length         = %d    \n", pCmd->ssu.ADC_length);
	printk("RecordLength       = %d    \n", pCmd->ssu.RecordLength);
	printk("BufferBaseAddress  = 0x%08x\n", pCmd->ssu.BufferBaseAddress);
	printk("BufferUsedSize     = 0x%08x\n", pCmd->ssu.BufferBaseSize);
	printk("BufferNumbers      = %d    \n", pCmd->ssu.BufferNumbers);
	printk("BufferSize         = %d    \n", pCmd->ssu.BufferSize);
	printk("ProcTime           = %d    \n\n", pCmd->ssu.ProcTime);

	MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
	return retval;
}
#endif
#ifdef QUEUE_STATS
#define IS_HW_BA    0
#define IS_SW_BA    1
#define NONE_BA     2

#ifdef NEWDP_ACNT_BA
void
PrintBAHisto(struct net_device *netdev, UINT8 staid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	WLAN_TX_BA_HIST *pBA = NULL;
	UINT32 i, data;
	UINT32 BAholecnt = 0, BAexpcnt = 0, bmap0cnt = 0, NoBAcnt = 0;
	UINT8 bmap0flag, NoBAflag, index;
	char buff[500], file_location[20];
	struct file *filp_bahisto = NULL;
	UINT8 *data_p = buff;

	extern UINT8 BA_HISTO_STAID_MAP[10];

	if (staid < 10)
		index = BA_HISTO_STAID_MAP[staid];
	else {
		printk("Print txba_histo staid %d out of range\n", staid);
		return;
	}

	pBA = (WLAN_TX_BA_HIST *) & wlpptr->wlpd_p->txBAStats[index];

	if (pBA->pBAStats == NULL)
		return;

	if ((pBA->pBAStats != NULL) && (pBA->Stnid != staid)) {
		printk("Print txba_histo staid %d not found\n", staid);
		return;
	}

	memset(buff, 0, sizeof(buff));
	memset(file_location, 0, sizeof(file_location));
	sprintf(file_location, "/tmp/ba_histo%d", staid);

	filp_bahisto = filp_open(file_location, O_RDWR | O_CREAT | O_TRUNC, 0);

	if (!IS_ERR(filp_bahisto)) {

		if (pBA->pBAStats != NULL) {

			printk("BA histogram staid:%d, type:%s\n", pBA->Stnid,
			       pBA->Type ? "MU" : "SU");

			data_p +=
				sprintf(data_p,
					"BA histogram staid:%d, type:%s\n",
					pBA->Stnid, pBA->Type ? "MU" : "SU");
			data_p +=
				sprintf(data_p, "%8s,%8s,%8s,%8s\n", "BAhole",
					"Expect", "Bmap0", "NoBA");

			data = *(UINT32 *) & pBA->pBAStats[0];
			BAholecnt = 0;
			BAexpcnt = 0;
			bmap0cnt = 0;
			NoBAcnt = 0;
			for (i = 0; i < ACNT_BA_SIZE && data; i++) {

				data = *(UINT32 *) & pBA->pBAStats[i];
				if (data == 0)
					break;

				/*If no BA event does not happen, check BA hole and BA expected to mark BA bitmap all 0 event */
				if (!pBA->pBAStats[i].NoBA)
					bmap0flag =
						(pBA->pBAStats[i].BAHole ==
						 pBA->pBAStats[i].
						 BAExpected) ? 1 : 0;
				else
					bmap0flag = 0;

				NoBAflag = pBA->pBAStats[i].NoBA;

				/*Buffer is full. Write to file and reset buf */
				if ((strlen(buff) + 16) >= 500) {
					__kernel_write(filp_bahisto, buff,
						       strlen(buff),
						       &filp_bahisto->f_pos);
					mdelay(2);
					memset(buff, 0, sizeof(buff));
					data_p = buff;

				}

				data_p +=
					sprintf(data_p, "%3d,%3d,",
						pBA->pBAStats[i].BAHole,
						pBA->pBAStats[i].BAExpected);

				BAholecnt += pBA->pBAStats[i].BAHole;
				BAexpcnt += pBA->pBAStats[i].BAExpected;

				if (bmap0flag) {
					data_p += sprintf(data_p, "  #,");
					bmap0cnt++;
				} else
					data_p +=
						sprintf(data_p, "%3d,",
							bmap0flag);

				if (NoBAflag) {
					data_p += sprintf(data_p, "  *\n");
					NoBAcnt++;
				} else
					data_p +=
						sprintf(data_p, "%3d\n",
							NoBAflag);

			}
		}

		__kernel_write(filp_bahisto, buff, strlen(buff),
			       &filp_bahisto->f_pos);
		filp_close(filp_bahisto, current->files);
		printk("Total BAhole:%u, BAExpected:%u, BAbitmap0:%u, NoBA:%u\n", (unsigned int)BAholecnt, (unsigned int)BAexpcnt, (unsigned int)bmap0cnt, (unsigned int)NoBAcnt);
		printk("Staid:%d BA histogram data written to %s\n", staid,
		       file_location);

	} else
		printk("Error opening /tmp/ba_histo! %p \n", filp_bahisto);

	mdelay(10);
}

#endif

/*Function to print txrate histogram*/
void
PrintTxHisto(struct net_device *netdev, UINT16 indx, UINT8 type)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int _11G_rate[IEEEtypes_MAX_DATA_RATES_G] =
		{ 1, 2, 5, 11, 22, 6, 9, 12, 18, 24, 36, 48, 54, 72 };
	char *bwStr[4] = { "ht20", "ht40", "ht80", "ht160" };
	char *sgiStr[2] = { "lgi", "sgi" };
#ifdef SOC_W906X
	char *sgi11axStr[5] =
		{ "1x0.8gi", "2x0.8gi", "2x1.6gi", "4x3.2gi", "4x0.8gi" };
#endif
	char *mode[3] = { "SU_MIMO rate", "MU_MIMO rate", " Custom rate" };
	UINT32 j, rateinfo, cnt, per0, per1, per2, per3, per4, total;
	UINT8 printed = 0, loopcnt, bw, sgi, nss, format;
	UINT16 mcs, ratemask;
	WLAN_TX_RATE_HIST_DATA *pTxhisto = NULL;

	if (wlpptr->wlpd_p->txRateHistogram[indx] == NULL)
		return;

	if (type == SU_MIMO) {
		loopcnt = RATE_ADAPT_MAX_SUPPORTED_RATES;
		pTxhisto = &(wlpptr->wlpd_p->txRateHistogram[indx]->SU_rate[0]);
	} else {
		loopcnt = TX_RATE_HISTO_CUSTOM_CNT;
		pTxhisto =
			&(wlpptr->wlpd_p->txRateHistogram[indx]->
			  custom_rate[0]);
	}

	printed = 0;
	total = 0;
	if (type == MU_MIMO) {
		for (nss = 0; nss < (QS_NUM_SUPPORTED_11AC_NSS - 1); nss++) {
			for (bw = 0; bw < QS_NUM_SUPPORTED_11AC_BW; bw++) {
				for (mcs = 0; mcs < QS_NUM_SUPPORTED_11AC_MCS;
				     mcs++) {
					for (sgi = 0; sgi < QS_NUM_SUPPORTED_GI;
					     sgi++) {
						cnt = ENDIAN_SWAP32(wlpptr->
								    wlpd_p->
								    txRateHistogram
								    [indx]->
								    MU_rate[nss]
								    [bw][sgi]
								    [mcs].cnt);
						rateinfo =
							ENDIAN_SWAP32(wlpptr->
								      wlpd_p->
								      txRateHistogram
								      [indx]->
								      MU_rate
								      [nss][bw]
								      [sgi]
								      [mcs].
								      rateinfo);

						if (cnt && (rateinfo > 0)) {
							total += cnt;
							per4 = ENDIAN_SWAP32
								(wlpptr->
								 wlpd_p->
								 txRateHistogram
								 [indx]->
								 MU_rate[nss]
								 [bw][sgi][mcs].
								 per[4]);
							per3 = ENDIAN_SWAP32
								(wlpptr->
								 wlpd_p->
								 txRateHistogram
								 [indx]->
								 MU_rate[nss]
								 [bw][sgi][mcs].
								 per[3]);
							per2 = ENDIAN_SWAP32
								(wlpptr->
								 wlpd_p->
								 txRateHistogram
								 [indx]->
								 MU_rate[nss]
								 [bw][sgi][mcs].
								 per[2]);
							per1 = ENDIAN_SWAP32
								(wlpptr->
								 wlpd_p->
								 txRateHistogram
								 [indx]->
								 MU_rate[nss]
								 [bw][sgi][mcs].
								 per[1]);
							per0 = ENDIAN_SWAP32
								(wlpptr->
								 wlpd_p->
								 txRateHistogram
								 [indx]->
								 MU_rate[nss]
								 [bw][sgi][mcs].
								 per[0]);

							if (printed == 0) {
								printk("%s %26s  <%2d       >=%2d       >=%2d       >=%2d       >=%2d\n", mode[type], " PER%", TX_HISTO_PER_THRES[0], TX_HISTO_PER_THRES[0], TX_HISTO_PER_THRES[1], TX_HISTO_PER_THRES[2], TX_HISTO_PER_THRES[3]);
								printk("TOTAL MPDU tx pkt: %ud\n", (unsigned int)wlpptr->wlpd_p->txRateHistogram[indx]->TotalTxCnt[type]);
								printed = 1;
							}

							if ((rateinfo & 0x3) ==
							    0)
								ratemask =
									0xfff;
#ifdef SOC_W906X
							/* HE skip gi bit 6 & 7 */
							else if ((rateinfo &
								  0x3) == 3)
								ratemask =
									0xff3f;
#endif
							else
								ratemask =
									0xffff;

							if ((wlpptr->wlpd_p->
							     txRateHistogram
							     [indx]->
							     CurRateInfo[type] &
							     ratemask) ==
							    (rateinfo &
							     ratemask))
								printk("*");	//mark as current rate
							else
								printk(" ");
							printk("%5s_%3s_%1dSS_MCS%2d : %10u, %9u, %9u, %9u, %9u, %9u\n", bwStr[bw], sgiStr[sgi], (nss + 1), mcs, (unsigned int)cnt, (unsigned int)per0, (unsigned int)per1, (unsigned int)per2, (unsigned int)per3, (unsigned int)per4);

						}
					}
				}
			}
		}
	} else {

		for (j = 0; j < loopcnt; j++) {

			rateinfo = ENDIAN_SWAP32(pTxhisto[j].rateinfo);
#ifndef SOC_W906X
			cnt = ENDIAN_SWAP32(pTxhisto[j].cnt);
			if (cnt && (rateinfo > 0)) {
				total += cnt;
#endif /* #ifndef SOC_W906X */
				per4 = ENDIAN_SWAP32(pTxhisto[j].per[4]);
				per3 = ENDIAN_SWAP32(pTxhisto[j].per[3]);
				per2 = ENDIAN_SWAP32(pTxhisto[j].per[2]);
				per1 = ENDIAN_SWAP32(pTxhisto[j].per[1]);
				per0 = ENDIAN_SWAP32(pTxhisto[j].per[0]);
#ifdef SOC_W906X
				cnt = per4 + per3 + per2 + per1 + per0;
				if (cnt && (rateinfo > 0)) {
					UINT8 dcm = 0, stbc = 0;
					cnt = ENDIAN_SWAP32(pTxhisto[j].cnt);
					total += cnt;
#endif
					if (printed == 0) {
						printk("%s %26s  <%2d       >=%2d       >=%2d       >=%2d       >=%2d\n", mode[type], " PER%", TX_HISTO_PER_THRES[0], TX_HISTO_PER_THRES[0], TX_HISTO_PER_THRES[1], TX_HISTO_PER_THRES[2], TX_HISTO_PER_THRES[3]);
						printk("TOTAL MPDU tx pkt: %u\n", (unsigned int)wlpptr->wlpd_p->txRateHistogram[indx]->TotalTxCnt[type % SU_MU_TYPE_CNT]);
						printed = 1;
					}

					format = (rateinfo & 0x3);
					mcs = (rateinfo >> 8) & 0x7f;
					bw = (rateinfo >> 4) & 0x3;
#ifdef SOC_W906X
					sgi = (rateinfo >> 6) & 0x3;
					dcm = (rateinfo >> 3) & 0x1;
					stbc = (rateinfo >> 2) & 0x1;

					if ((format == 3) && (dcm && stbc)) {
						sgi = 4;	// 4x+0.8
					}
#else
					sgi = (rateinfo >> 6) & 0x1;
#endif

					if ((rateinfo & 0x3) == 0)
						ratemask = 0xfff;
#ifdef SOC_W906X
					/* HE skip gi bit 6 & 7 */
					else if ((rateinfo & 0x3) == 3)
						ratemask = 0xff3f;
#endif
					else
						ratemask = 0xffff;

					if ((wlpptr->wlpd_p->
					     txRateHistogram[indx]->
					     CurRateInfo[type %
							 SU_MU_TYPE_CNT] &
					     ratemask) == (rateinfo & ratemask))
						printk("*");	//mark as current rate
					else
						printk(" ");
					if (format == 0) {
						if (mcs == 2)
							printk("5.5Mbps             : %10u, %9u, %9u, %9u, %9u, %9u\n", (unsigned int)cnt, (unsigned int)per0, (unsigned int)per1, (unsigned int)per2, (unsigned int)per3, (unsigned int)per4);
						else if (mcs <
							 IEEEtypes_MAX_DATA_RATES_G)
							printk("%-3dMbps             : %10u, %9u, %9u, %9u, %9u, %9u\n", _11G_rate[mcs], (unsigned int)cnt, (unsigned int)per0, (unsigned int)per1, (unsigned int)per2, (unsigned int)per3, (unsigned int)per4);

					} else if (format == 1) {
						printk("%4s_%3s_MCS%2d	    : %10u, %9u, %9u, %9u, %9u, %9u\n", bwStr[bw], sgiStr[sgi], mcs, (unsigned int)cnt, (unsigned int)per0, (unsigned int)per1, (unsigned int)per2, (unsigned int)per3, (unsigned int)per4);
					} else {
						nss = (mcs >> 4);
						printk("%5s_%3s_%1dSS_MCS%2d : %10u, %9u, %9u, %9u, %9u, %9u\n",
#ifdef SOC_W906X
						       bwStr[bw],
						       (format ==
							3) ? sgi11axStr[sgi] :
						       sgiStr[sgi], (nss + 1),
						       (mcs & 0xf),
						       (unsigned int)cnt,
						       (unsigned int)per0,
						       (unsigned int)per1,
						       (unsigned int)per2,
						       (unsigned int)per3,
						       (unsigned int)per4);
#else
						       bwStr[bw], sgiStr[sgi],
						       (nss + 1), (mcs & 0xf),
						       (unsigned int)cnt,
						       (unsigned int)per0,
						       (unsigned int)per1,
						       (unsigned int)per2,
						       (unsigned int)per3,
						       (unsigned int)per4);
#endif

					}
				}
			}
		}

		if (printed)
			printk("  TOTAL              : %10u\n\n",
			       (unsigned int)total);
	}

#ifdef SOC_W906X
	void PrintSchHisto(struct net_device *netdev, UINT16 stnId,
			   char *sysfs_buff) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		int i, j;

		if ((stnId >= sta_num) ||
		    (wlpptr->wlpd_p->scheHistogram[stnId] == NULL))
			return;

		for (i = 0; i < 2; i++) {
			Sysfs_Printk("%sAmpdu scheduler stats\n",
				     i ? "" : "Non-");
			Sysfs_Printk
				("Delay\n          <1m         <10m        <100m        <300m        >300m\n");
			Sysfs_Printk("   %10u   %10u   %10u   %10u   %10u\n",
				     wlpptr->wlpd_p->scheHistogram[stnId]->
				     Delay[i][0]
				     ,
				     wlpptr->wlpd_p->scheHistogram[stnId]->
				     Delay[i][1]
				     ,
				     wlpptr->wlpd_p->scheHistogram[stnId]->
				     Delay[i][2]
				     ,
				     wlpptr->wlpd_p->scheHistogram[stnId]->
				     Delay[i][3]
				     ,
				     wlpptr->wlpd_p->scheHistogram[stnId]->
				     Delay[i][4]);
			Sysfs_Printk
				("\nBytes\n         <1500       <16k           <32k         <64k        <128k        >128k\n");
			Sysfs_Printk
				("   %10u   %10u   %10u   %10u   %10u   %10u\n\n",
				 wlpptr->wlpd_p->scheHistogram[stnId]->
				 NumBytes[i][0]
				 ,
				 wlpptr->wlpd_p->scheHistogram[stnId]->
				 NumBytes[i][1]
				 ,
				 wlpptr->wlpd_p->scheHistogram[stnId]->
				 NumBytes[i][2]
				 ,
				 wlpptr->wlpd_p->scheHistogram[stnId]->
				 NumBytes[i][3]
				 ,
				 wlpptr->wlpd_p->scheHistogram[stnId]->
				 NumBytes[i][4]
				 ,
				 wlpptr->wlpd_p->scheHistogram[stnId]->
				 NumBytes[i][5]);
			for (j = 0; j < 65; j++) {
				if (wlpptr->wlpd_p->scheHistogram[stnId]->
				    NumAmpdu[i][j])
					Sysfs_Printk("%sampdu[%2d] -  %10u\n",
						     i ? "" : "Non-", j,
						     wlpptr->wlpd_p->
						     scheHistogram[stnId]->
						     NumAmpdu[i][j]);
			}
			Sysfs_Printk("\n");
		}
	}

	int wlFwGetQueueStats(struct net_device *netdev, int option,
			      UINT8 fromHM, char *sysfs_buff)
#else
	int wlFwGetQueueStats(struct net_device *netdev, int option,
			      char *sysfs_buff)
#endif
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		int i;
		HostCmd_GET_QUEUE_STATS *pCmd =
			(HostCmd_GET_QUEUE_STATS *) & wlpptr->pCmdBuf[0];

#ifdef QUEUE_STATS_CNT_HIST
		QS_COUNTERS_t *pQS_Counters = &(pCmd->QueueStats.qs_u.Counters);
		QS_RETRY_HIST_t *pQS_RetryHist =
			&(pCmd->QueueStats.qs_u.RetryHist);
		int bw, sgi, nss;
		int SwBaQIndx[4] = { 7, 0, 1, 2 };
#endif
#ifdef QUEUE_STATS_LATENCY
		QS_LATENCY_t *pQS_Latency = &(pCmd->QueueStats.qs_u.Latency);
#endif
		unsigned long flags;
		int retval = 0;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_GET_QUEUE_STATS));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_QUEUE_STATS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_GET_QUEUE_STATS));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = (UINT8) option;

		dispRxPacket = (dispRxPacket + 1) & 0x01;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_GET_QUEUE_STATS));
		if (wlexecuteCommand(netdev, HostCmd_CMD_GET_QUEUE_STATS)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			printk("failed execution\n");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
#ifdef SOC_W906X
		//request from HM
		if (fromHM == 1) {
			wlmon_log_pfw_schInfo(netdev,
					      &(pCmd->QueueStats.qs_u.
						TxScheInfo));
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return retval;
		}
#endif

		switch (option & 0xf) {
		case QS_GET_TX_SCHEDULER_INFO:
			{
				QS_TX_SCHEDULER_INFO_t *pQS_Sched =
					&(pCmd->QueueStats.qs_u.TxScheInfo);
#ifdef SOC_W906X
				vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
				extStaDb_StaInfo_t *pStaInfo = NULL;
				UINT32 entries = 0;
				UINT8 *staBuf = NULL;
				UINT8 *listBuf = NULL;
				int idx;
#endif /* SOC_W906X */
				char s[12][14] = {
					"TimeoutCnt",
					"MaxAggrCnt",
					"NumMpduCnt",
					"NumMpdu   ",
					"NumByteCnt",
					"NumBytes  ",
#ifdef SOC_W906X
					"TimeoutCt2",
#else
					"          ",
#endif
					"          ",
					"AmpdLenMax",
					"          ",
					"          ",
					"Density   "
				};

				Sysfs_Printk("\nPFW scheduler info\n");
				for (i = 0; i < 12; i++) {
					Sysfs_Printk("%s:\t%10u\n", s[i],
						     ENDIAN_SWAP32((int)
								   pQS_Sched->
								   debug_scheduler
								   [i]));
				}
				Sysfs_Printk
					("\tNumMpdu   \tNumBytes  \tTimeDelay\n");
				for (i = 0; i < 10; i++) {
					Sysfs_Printk("\t%10u\t%10u\t%10u\n",
						     ENDIAN_SWAP32((int)
								   pQS_Sched->
								   debug_scheduler2
								   [i][0]),
						     ENDIAN_SWAP32((int)
								   pQS_Sched->
								   debug_scheduler2
								   [i][1]),
						     ENDIAN_SWAP32((int)
								   pQS_Sched->
								   debug_scheduler2
								   [i][2]));
				}
#ifdef SOC_W906X
				entries = extStaDb_entries(vmacSta_p, 0);
				if (entries) {
					staBuf = wl_kmalloc(entries *
							    sizeof(STA_INFO),
							    GFP_ATOMIC);
					if (staBuf == NULL)
						break;

					extStaDb_list(vmacSta_p, staBuf, 1);

					listBuf = staBuf;
					Sysfs_Printk
						("\nPer STA scheduler info\n");
					for (idx = 0; idx < entries; idx++) {
						if ((pStaInfo =
						     extStaDb_GetStaInfo
						     (vmacSta_p,
						      (IEEEtypes_MacAddr_t *)
						      listBuf,
						      STADB_DONT_UPDATE_AGINGTIME))
						    != NULL) {
							if (pStaInfo->State ==
							    ASSOCIATED) {
								Sysfs_Printk
									("\n###StnId: %d MAC Addr: %s###\n",
									 pStaInfo->
									 StnId,
									 mac_display
									 (pStaInfo->
									  Addr));
								PrintSchHisto
									(netdev,
									 pStaInfo->
									 StnId,
									 sysfs_buff);
							}
							listBuf +=
								sizeof
								(STA_INFO);
						}
					}
					wl_kfree(staBuf);
				} else {
					if (vmacSta_p->OpMode == WL_OP_MODE_STA
					    || vmacSta_p->OpMode ==
					    WL_OP_MODE_VSTA) {
						Sysfs_Printk("\n");
						PrintSchHisto(netdev, 0,
							      sysfs_buff);
					} else
						Sysfs_Printk
							("\nPer STA scheduler info\nNo STA connected.\n\n");
				}
#endif /* #ifdef SOC_W906X */
				break;
			}
#ifdef QUEUE_STATS_LATENCY
		case QS_GET_TX_LATENCY:
			{
				WLDBG_PRINT_QUEUE_STATS_LATENCY;
				printk("\nFW Packet Latency (microsecond)\n");
				printk("TCQ\t   FW_Min\t   FW_Max\t  FW_Mean\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Latency->TCQxFwLatency[i].Max) {
						printk("%2d    %10u\t%10u\t%10u\n", i, ENDIAN_SWAP32((int)pQS_Latency->TCQxFwLatency[i].Min)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxFwLatency
								     [i].Max)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxFwLatency
								     [i].Mean));
					}
				}
				printk("TCQ\t  MAC_Min\t  MAC_Max\t MAC_Mean\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Latency->TCQxMacLatency[i].Max) {
						printk("%2d    %10u\t%10u\t%10u\n", i, ENDIAN_SWAP32((int)pQS_Latency->TCQxMacLatency[i].Min)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxMacLatency
								     [i].Max)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxMacLatency
								     [i].Mean));
					}
				}
				printk("TCQ\tMAC_HW_Min\tMAC_HW_Max\tMAC_HW_Mean\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Latency->TCQxMacHwLatency[i].
					    Max) {
						printk("%2d    %10u\t%10u\t%10u\n", i, ENDIAN_SWAP32((int)pQS_Latency->TCQxMacHwLatency[i].Min)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxMacHwLatency
								     [i].Max)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxMacHwLatency
								     [i].Mean));
					}
				}
				printk("TCQ\tTotal_Min\tTotal_Max\tTotal_Mean\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Latency->TCQxTotalLatency[i].
					    Max) {
						printk("%2d    %10u\t%10u\t%10u\n", i, ENDIAN_SWAP32((int)pQS_Latency->TCQxTotalLatency[i].Min)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxTotalLatency
								     [i].Max)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxTotalLatency
								     [i].Mean)
							);
					}
				}
				printk("\nQueue Size\n");
				printk("TCQ\t     Min\t      Max\t     Mean\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Latency->TCQxQSize[i].Max) {
						printk("%2d    %10u\t%10u\t%10u\n", i, ENDIAN_SWAP32((int)pQS_Latency->TCQxQSize[i].Min >> 4)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxQSize
								     [i].
								     Max >> 4)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Latency->
								     TCQxQSize
								     [i].
								     Mean >>
								     4));
					}
				}

				break;
			}
		case QS_GET_RX_LATENCY:
			{
				printk("\nRX: FW Packet Latency (microsecond)\n");
				printk("FW_Min\t   FW_Max\t  FW_Mean\n");
				printk("%10u\t%10u\t%10u\n",
				       ENDIAN_SWAP32((int)pQS_Latency->
						     RxFWLatency.Min)
				       ,
				       ENDIAN_SWAP32((int)pQS_Latency->
						     RxFWLatency.Max)
				       ,
				       ENDIAN_SWAP32((int)pQS_Latency->
						     RxFWLatency.Mean));

				WLDBG_PRINT_QUEUE_STATS_RX_LATENCY;
				break;
			}
#endif
#ifdef QUEUE_STATS_CNT_HIST
		case QS_GET_TX_COUNTER:
			{
				int j;
				WLDBG_PRINT_QUEUE_STATS_COUNTERS;
				printk("\n------------------------\n");
				printk("TX: FW Packet Statistics\n");
				printk("------------------------");
				printk("\nNon-AMPDU Packet Counters\n");
				printk("TCQ\tAttempts\tSuccesses\tSuccess_with_Retries\t  Failures\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Counters->TCQxAttempts[i]) {
						printk("%2d    %10u\t%10u\t    %10u\t\t%10u\n", i, ENDIAN_SWAP32((int)pQS_Counters->TCQxAttempts[i])
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     TCQxSuccesses
								     [i])
						       ,
						       (ENDIAN_SWAP32
							((int)pQS_Counters->
							 TCQxRetrySuccesses[i])
							+
							ENDIAN_SWAP32((int)
								      pQS_Counters->
								      TCQxMultipleRetrySuccesses
								      [i]))
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     TCQxFailures
								     [i]));
					}
				}

				printk("\nPacket Per Second\n");
				printk("TCQ\tPPS_Min\t\t  PPS_Max\t\t PPS_Mean\n");
				for (i = 0; i < NUM_OF_TCQ; i++) {
					if (pQS_Counters->TCQxPktRates[i].Max) {
						printk("%2d    %10u\t%10u\t     %10u\n", i, ENDIAN_SWAP32((int)pQS_Counters->TCQxPktRates[i].Min)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     TCQxPktRates
								     [i].Max)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     TCQxPktRates
								     [i].Mean));
					}
				}
				printk("\nHW Block Ack Stream Counters\n");
				printk("Stream\tEnqueued\tAttempts\tSuccesses\t Retry\t       BAR     Failures\n");
				for (i = 0; i < NUM_OF_HW_BA; i++) {
					if (pQS_Counters->BAxStreamStats[i].
					    BaPktEnqueued) {
						printk(" %d    %10u      %10u       %10u   %10u  %10u   %10u\n", i, ENDIAN_SWAP32((int)pQS_Counters->BAxStreamStats[i].BaPktEnqueued)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     BAxStreamStats
								     [i].
								     BaPktAttempts)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     BAxStreamStats
								     [i].
								     BaPktSuccess)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     BAxStreamStats
								     [i].
								     BaRetryCnt)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     BAxStreamStats
								     [i].BarCnt)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     BAxStreamStats
								     [i].
								     BaPktFailures));
					}
				}

				printk("\nSW BA Stream Counters\n");
				printk("QID   Enqueued      TxDone  Total_Retry  QNotReady      QFull  DropNonBa   WrongQid     DropMc   FailHwEnQ\n");
				for (i = 0; i < QS_NUM_STA_SUPPORTED; i++) {
					if (pQS_Counters->SwBAStats[i].
					    SwBaPktEnqueued) {
						printk("%2d  %10u  %10u   %10u %10u %10u %10u %10u %10u %10u\n", SwBaQIndx[i]
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaPktEnqueued)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaPktDone)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaRetryCnt)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaQNotReadyDrop)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaQFullDrop)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaDropNonBa)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaWrongQid)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaDropMc)
						       ,
						       ENDIAN_SWAP32((int)
								     pQS_Counters->
								     SwBAStats
								     [i].
								     SwBaFailHwEnQ));
					}
				}
				for (i = 0; i < QS_NUM_STA_SUPPORTED; i++) {
					if (pQS_Counters->SwBAStats[i].
					    SwBaPktEnqueued) {
						SWBA_LFTM_STATS_t SBLTS;

						memset((void *)&SBLTS, 0x00,
						       sizeof(SBLTS));
						if (wlFwGetAddrValue
						    (netdev,
						     pQS_Counters->SwBAStats[i].
						     pSBLTS,
						     (sizeof(SWBA_LFTM_STATS_t)
						      >> 2), (UINT32 *) & SBLTS,
						     0) == SUCCESS) {
							int k;
							printk("\nQID=%d Life Time Expiration drop=%u\n", SwBaQIndx[i], SBLTS.SBLT_ExpiredCnt);
							if (SBLTS.
							    SBLT_ExpiredCnt) {
								printk("      num_Retry\t   Packets\n");
								for (k = 0;
								     k < 63;
								     k++) {
									if (SBLTS.SBLT_Retry[k])
										printk("\t%2d \t%10u\n", k, SBLTS.SBLT_Retry[k]);
								}
							}
						} else {
							printk("Could not get the SwBa Life Time Error Info\n");
						}
					}
				}

				printk("\nPer STA counters\n");
				printk("----------------\n");
				printk("MAC address\t\t Attempts\tSuccesses\tSuccess_with_Retries\t  Failures\n");
				for (j = 0; j < QS_NUM_STA_SUPPORTED; j++) {
					char *ba_str[3] =
						{ "[HwBa]", "[SwBa]",
					      "      " };
					if (!ENDIAN_SWAP16
					    ((int)pQS_Counters->StaCounters[j].
					     valid)) {
						continue;
					}
					printk("%02x:%02x:%02x:%02x:%02x:%02x%s ", pQS_Counters->StaCounters[j].addr[0], pQS_Counters->StaCounters[j].addr[1], pQS_Counters->StaCounters[j].addr[2], pQS_Counters->StaCounters[j].addr[3], pQS_Counters->StaCounters[j].addr[4], pQS_Counters->StaCounters[j].addr[5], ba_str[wlCheckBa(netdev, pQS_Counters->StaCounters[j].addr)]);

					printk("%10u\t%10u\t%10u\t\t%10u\n",
					       ENDIAN_SWAP32((int)pQS_Counters->
							     StaCounters[j].
							     TxAttempts)
					       ,
					       ENDIAN_SWAP32((int)pQS_Counters->
							     StaCounters[j].
							     TxSuccesses)
					       ,
					       (ENDIAN_SWAP32
						((int)pQS_Counters->
						 StaCounters[j].
						 TxRetrySuccesses)
						+
						ENDIAN_SWAP32((int)
							      pQS_Counters->
							      StaCounters[j].
							      TxMultipleRetrySuccesses))
					       ,
					       ENDIAN_SWAP32((int)pQS_Counters->
							     StaCounters[j].
							     TxFailures));
				}
				printk("\n\n---------------\n");
				printk("Rx Pkt counters\n");
				printk("---------------\n");
				printk("MAC address\t\tFw_RxEntry\tDrv_RxEntry\tDrv_80211Input\tDrv_Forwarder\n");
				for (j = 0; j < 4; j++) {
					if (pQS_Counters->rxStaCounters[j].
					    valid) {
						printk("%02x:%02x:%02x:%02x:%02x:%02x\t", pQS_Counters->rxStaCounters[j].addr[0], pQS_Counters->rxStaCounters[j].addr[1], pQS_Counters->rxStaCounters[j].addr[2], pQS_Counters->rxStaCounters[j].addr[3], pQS_Counters->rxStaCounters[j].addr[4], pQS_Counters->rxStaCounters[j].addr[5]);
						printk("%10u\t%10u\t%10u\t%10u\n", ENDIAN_SWAP32((int)pQS_Counters->rxStaCounters[j].rxPktCounts), rxPktStats_sta[j].RxRecvPollCnt, rxPktStats_sta[j].Rx80211InputCnt, rxPktStats_sta[j].RxfwdCnt);
					} else {
						break;
					}
				}
				break;
			}
		case QS_GET_RETRY_HIST:
			{
				int j;
				UINT32 RetryHist[NUM_OF_RETRY_BIN];
				QS_RETRY_HIST_t qsRH;

				memset((void *)&RetryHist[0], 0x00,
				       sizeof(RetryHist));
				memcpy((void *)&qsRH, (void *)pQS_RetryHist,
				       sizeof(QS_RETRY_HIST_t));
				printk("\nPacket Retry Histogram");
				for (j = 0; j < NUM_OF_TCQ; j++) {
					if (qsRH.TotalPkts[j]) {
						if (wlFwGetAddrValue
						    (netdev,
						     qsRH.
						     TxPktRetryHistogram[j],
						     NUM_OF_RETRY_BIN,
						     (UINT32 *) RetryHist,
						     0) == SUCCESS) {
							printk("\n  num_Retry\t   Packets\tQID=%d\tTotal packets = %u\n", j, qsRH.TotalPkts[j]);
							for (i = 0;
							     i <
							     NUM_OF_RETRY_BIN;
							     i++) {
								if (RetryHist
								    [i]) {
									printk("\t%2d \t%10u\n", i, ENDIAN_SWAP32((int)RetryHist[i]));
								}
							}
						}
					}
				}
				break;
			}

#ifdef NEWDP_ACNT_BA
		case QS_GET_BA_HIST:
			{
				int staid = option >> 4;
				PrintBAHisto(netdev, staid);

				break;
			}
#endif
		case QS_GET_TX_RATE_HIST:
			{

				int indx = option >> 4;

				PrintTxHisto(netdev, indx, SU_MIMO);	//SU rate
				PrintTxHisto(netdev, indx, MU_MIMO);	//MU rate
				PrintTxHisto(netdev, indx, 2);	//Custom rate

				printk("============================\n");

				break;
			}

		case QS_GET_RX_RATE_HIST:
			{
				int _11G_rate[14] =
					{ 1, 2, 5, 11, 22, 6, 9, 12, 18, 24, 36,
				    48, 54, 72 };
				char *bwStr[4] =
					{ "ht20", "ht40", "ht80", "ht160" };
				char *vhtbwStr[4] =
					{ "vht20", "vht40", "vht80", "vht160" };
				char *sgiStr[2] = { "lgi", "sgi" };

				char *hebwStr[4] =
					{ "he20", "he40", "he80", "he160" };

				{
					printk("\nRx Data Frame Rate Histogram \n");
					printk("============================\n");
#ifdef SOC_W906X
#ifdef RXACNT_REC
					{
						DRV_RATE_HIST *prxRateHistogram
							=
							&wlpptr->wlpd_p->
							drvrxRateHistogram;
						printk("pktcnt(mgmt, ctrl, data)=(%u, %u, %u)\n", prxRateHistogram->pkt_cnt[0], prxRateHistogram->pkt_cnt[1], prxRateHistogram->pkt_cnt[2]);
					}
#endif //RXACNT_REC
					for (i = 0; i < QS_MAX_DATA_RATES_G;
					     i++) {
						{
							if (ENDIAN_SWAP32
							    (wlpptr->wlpd_p->
							     rxRateHistogram.
							     LegacyRates[i]) >
							    0) {
								if (i == 2) {
									printk("5.5Mbps \t: %10u\n", ENDIAN_SWAP32((unsigned int)wlpptr->wlpd_p->rxRateHistogram.LegacyRates[i]));
								} else {
									printk("%2dMbps  \t: %10u\n", _11G_rate[i]
									       ,
									       ENDIAN_SWAP32
									       ((unsigned int)wlpptr->wlpd_p->rxRateHistogram.LegacyRates[i]));
								}
							}
						}
					}
					for (bw = 0;
					     bw < QS_NUM_SUPPORTED_11N_BW;
					     bw++) {
						for (sgi = 0;
						     sgi < QS_NUM_SUPPORTED_GI;
						     sgi++) {
							for (i = 0;
							     i <
							     QS_NUM_SUPPORTED_MCS;
							     i++) {
								{
									if (ENDIAN_SWAP32(wlpptr->wlpd_p->drvrxRateHistogram.HtRates[bw][sgi][i]) > 0) {
										printk("%4s_%3s_MCS%2d  : %10u\n", bwStr[bw], sgiStr[sgi], i, ENDIAN_SWAP32((unsigned int)wlpptr->wlpd_p->drvrxRateHistogram.HtRates[bw][sgi][i]));
									}
								}
							}
						}
					}
					for (nss = 0;
					     nss <
					     QS_NUM_SUPPORTED_11AC_NSS_BIG;
					     nss++) {
						for (bw = 0;
						     bw <
						     QS_NUM_SUPPORTED_11AC_BW;
						     bw++) {
							for (i = 0;
							     i <
							     QS_NUM_SUPPORTED_11AC_MCS;
							     i++) {
								for (sgi = 0;
								     sgi <
								     QS_NUM_SUPPORTED_GI;
								     sgi++) {
									if (ENDIAN_SWAP32(wlpptr->wlpd_p->drvrxRateHistogram.VHtRates[nss][bw][sgi][i]) > 0) {
										printk("%4s_%3s_%1dSS_MCS%2d  : %10u\n", vhtbwStr[bw], sgiStr[sgi], (nss + 1), i, ENDIAN_SWAP32(((int)wlpptr->wlpd_p->drvrxRateHistogram.VHtRates[nss][bw][sgi][i])));
									}
								}
							}
						}
					}
					for (nss = 0;
					     nss < QS_NUM_SUPPORTED_11AX_NSS;
					     nss++) {
						for (bw = 0;
						     bw <
						     QS_NUM_SUPPORTED_11AX_BW;
						     bw++) {
							for (i = 0;
							     i <
							     QS_NUM_SUPPORTED_11AX_MCS;
							     i++) {
								for (sgi = 0;
								     sgi <
								     QS_NUM_SUPPORTED_11AX_GILTF_EXT;
								     sgi++) {
									if (ENDIAN_SWAP32(wlpptr->wlpd_p->drvrxRateHistogram.HERates[nss][bw][sgi][i]) > 0) {
										printk("%4s_giltf[%d]_%1dSS_MCS%2d  : %10u\n", hebwStr[bw], sgi, (nss + 1), i, ENDIAN_SWAP32(((int)wlpptr->wlpd_p->drvrxRateHistogram.HERates[nss][bw][sgi][i])));
									}
								}
							}
						}
					}
#endif
					printk("============================\n");
				}
				break;
			}
#endif
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwResetQueueStats(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		FWCmdHdr *pCmd = (FWCmdHdr *) & wlpptr->pCmdBuf[0];

		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(FWCmdHdr));
		pCmd->Cmd = ENDIAN_SWAP16(HostCmd_CMD_RESET_QUEUE_STATS);
		pCmd->Length = ENDIAN_SWAP16(sizeof(FWCmdHdr));
		pCmd->SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		dispRxPacket = (dispRxPacket + 1) & 0x01;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(FWCmdHdr));
		if (wlexecuteCommand(netdev, HostCmd_CMD_RESET_QUEUE_STATS)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		wldbgResetQueueStats();
		if (numOfRxSta) {
			wlFwSetMacSa(netdev, numOfRxSta, qs_rxMacAddrSave);
		}
		printk("queue_stats reset ok!\n");
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return 0;
	}

	int wlFwSetMacSa(struct net_device *netdev, int n, UINT8 * addr) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_QSTATS_SET_SA *pCmd =
			(HostCmd_QSTATS_SET_SA *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_QSTATS_SET_SA));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_QSTATS_SET_SA);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_QSTATS_SET_SA));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		memcpy(pCmd->Addr, addr, (sizeof(IEEEtypes_MacAddr_t) * n));
		pCmd->NumOfAddrs = n;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_QSTATS_SET_SA));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_QSTATS_SET_SA);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

/*Get MAC addr to be kicked out when consecutive tx failure cnt > limit*/
	int wlFwGetConsecTxFailAddr(struct net_device *netdev,
				    IEEEtypes_MacAddr_t * addr) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_CONSEC_TXFAIL_ADDR *pCmd =
			(HostCmd_FW_GET_CONSEC_TXFAIL_ADDR *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_CONSEC_TXFAIL_ADDR));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_GET_CONSEC_TXFAIL_ADDR);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_GET_CONSEC_TXFAIL_ADDR));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_GET_CONSEC_TXFAIL_ADDR));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_GET_CONSEC_TXFAIL_ADDR);

		if (!retval)
			memcpy(addr, pCmd->Addr, sizeof(IEEEtypes_MacAddr_t));

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

/*Set consective tx failure limit. When consecutive tx failure cnt > limit, client will be kicked out*/
	int wlFwSetConsecTxFailLimit(struct net_device *netdev, UINT32 value) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_TXFAILLIMIT *pCmd =
			(HostCmd_FW_TXFAILLIMIT *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_TXFAILLIMIT));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_TXFAILLIMIT);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_TXFAILLIMIT));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->txfaillimit = ENDIAN_SWAP32(value);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_TXFAILLIMIT));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_TXFAILLIMIT);

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwGetConsecTxFailLimit(struct net_device *netdev, UINT32 * value) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_TXFAILLIMIT *pCmd =
			(HostCmd_FW_TXFAILLIMIT *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_TXFAILLIMIT));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_TXFAILLIMIT);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_TXFAILLIMIT));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_TXFAILLIMIT));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_TXFAILLIMIT);
		if (!retval)
			*value = ENDIAN_SWAP32(pCmd->txfaillimit);

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlCheckBa(struct net_device *netdev, UINT8 * addr) {
		struct wlprivate *priv =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		int i;

		for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING; i++) {
			if (memcmp(priv->wlpd_p->Ampdu_tx[i].MacAddr, addr, 6)
			    == 0) {
				if (i < 2)
					return IS_HW_BA;
				else
					return IS_SW_BA;
			}
		}
		return NONE_BA;
	}
#endif

	int wlFwSetBWSignalType(struct net_device *netdev, UINT32 mode,
				UINT8 val) {
		int retval = FAIL;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_BW_SIGNALLING *pCmd =
			(HostCmd_FW_SET_BW_SIGNALLING *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

#ifdef MFG_SUPPORT
		if (wlpptr->mfgEnable) {
			return SUCCESS;
		}
#endif
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_BW_SIGNALLING));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_BW_SIGNALLING);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_BW_SIGNALLING));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Action = ENDIAN_SWAP32(WL_SET);
		pCmd->Mode = ENDIAN_SWAP32(mode);
		pCmd->Bitmap = val;
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_SET_BW_SIGNALLING);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

/*Once VHT Operating Mode is received, we update peer VHT channel bandwidth and Rx Nss in peer info*/
#ifdef SOC_W906X
	int wlFwSetVHTOpMode(struct net_device *netdev, UINT16 staid,
			     UINT8 vht_NewRxChannelWidth, UINT8 vht_NewRxNss)
#else
	int wlFwSetVHTOpMode(struct net_device *netdev,
			     IEEEtypes_MacAddr_t * staaddr,
			     UINT8 vht_NewRxChannelWidth, UINT8 vht_NewRxNss)
#endif
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_VHT_OP_MODE *pCmd =
			(HostCmd_FW_VHT_OP_MODE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_VHT_OP_MODE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_VHT_OP_MODE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_VHT_OP_MODE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;

		pCmd->vht_NewRxChannelWidth = vht_NewRxChannelWidth;
		pCmd->vht_NewRxNss = vht_NewRxNss;
#ifdef SOC_W906X
		pCmd->staid = ENDIAN_SWAP16(staid);
#else
		memcpy(pCmd->Addr, staaddr, sizeof(IEEEtypes_MacAddr_t));
#endif

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_VHT_OP_MODE));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_VHT_OP_MODE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

#ifdef WNC_LED_CTRL
	int wlFwLedOn(struct net_device *netdev, UINT8 led_on) {

		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_LED_CTRL *pCmd =
			(HostCmd_FW_LED_CTRL *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_LED_CTRL));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_LED_CTRL);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_LED_CTRL));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->led_on = led_on;

		retval = wlexecuteCommand(netdev, HostCmd_CMD_LED_CTRL);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
#endif
/* This Function is Used to Collect the Core Dump from F/W
 * The Core Dump is collected in Chunks of 4KB buffer
 * F/W Returns the Core Dump Memory in Memory Mapped Region (i.e in pCmdBuf)
 */
	int wlFwGetCoreSniff(struct net_device *netdev,
			     coredump_cmd_t * core_dump, char *buff) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_CORE_DUMP *pCmd =
			(HostCmd_FW_CORE_DUMP *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_CORE_DUMP));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_FW_CORE_DUMP);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_CORE_DUMP));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->cmd_data.coredump.context =
			ENDIAN_SWAP32(core_dump->context);
		pCmd->cmd_data.coredump.buffer =
			(UINT32) wlpptr->wlpd_p->pPhysCmdBuf +
			sizeof(HostCmd_FW_CORE_DUMP) -
			sizeof(HostCmd_FW_CORE_DUMP_);
		pCmd->cmd_data.coredump.buffer_len =
			ENDIAN_SWAP32(MAX_CORE_DUMP_BUFFER);
		pCmd->cmd_data.coredump.sizeB = ENDIAN_SWAP32(core_dump->sizeB);
		pCmd->cmd_data.coredump.flags = ENDIAN_SWAP32(core_dump->flags);

		//printk("\ncoredump->context=0x%x, coredump->buffer=0x%x, coredump->buffer_len=0x%x, coredump->sizeB=0x%x\n",
		//          pCmd->cmd_data.coredump.context, pCmd->cmd_data.coredump.buffer, pCmd->cmd_data.coredump.buffer_len, pCmd->cmd_data.coredump.sizeB);

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_CORE_DUMP));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_FW_CORE_DUMP);
		if (retval == SUCCESS)
			retval = (ENDIAN_SWAP16(pCmd->CmdHdr.Result) ==
				  HostCmd_RESULT_OK) ? SUCCESS : FAIL;
		/*Update Core Dump Buffer */
		core_dump->context =
			ENDIAN_SWAP32(pCmd->cmd_data.coredump.context);
		core_dump->flags = ENDIAN_SWAP32(pCmd->cmd_data.coredump.flags);
		core_dump->sizeB = ENDIAN_SWAP32(pCmd->cmd_data.coredump.sizeB);
#ifdef SOC_W906X
		memcpy(buff, pCmd->Buffer, MAX_CORE_DUMP_BUFFER);
#else
		memcpy(buff,
		       (const void *)((UINT32) pCmd +
				      sizeof(HostCmd_FW_CORE_DUMP) -
				      sizeof(HostCmd_FW_CORE_DUMP_)),
		       MAX_CORE_DUMP_BUFFER);
#endif
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

#ifdef SOC_W906X
/*
	This function should be called when pfw is in diagmode  
*/
	int wlFwGetCoreDumpAddrValue(struct net_device *netdev, UINT32 addr,
				     UINT32 len, UINT32 * val, UINT16 set) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_CORE_DUMP *pCmd =
			(HostCmd_FW_CORE_DUMP *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		debug_mem_cmd_t *pdmCmd;

		if (set == 0 && !val)
			return retval;

		WLDBG_ENTER(DBG_LEVEL_1);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_CORE_DUMP));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_GET_FW_CORE_MEM_DUMP);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_CORE_DUMP));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pdmCmd = (debug_mem_cmd_t *) & (pCmd->cmd_data.debug_mem);
		pdmCmd->set = set;
		pdmCmd->type = DEBUG_LOCAL_MEM;
		pdmCmd->addr = addr;
		pdmCmd->val = len;

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_CORE_DUMP));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_GET_FW_CORE_MEM_DUMP);
		if (!retval) {
			if (set == 0) {	//get
				memcpy((void *)val, (void *)pCmd->Buffer,
				       (sizeof(u32) * pdmCmd->val));
			}
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

#endif

	int wlFwGetCoreDump(struct net_device *netdev,
			    coredump_cmd_t * core_dump, char *buff) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_CORE_DUMP *pCmd =
			(HostCmd_FW_CORE_DUMP *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_CORE_DUMP));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_FW_CORE_DUMP);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_CORE_DUMP));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->cmd_data.coredump.context =
			ENDIAN_SWAP32(core_dump->context);
		pCmd->cmd_data.coredump.buffer =
			(UINT32) wlpptr->wlpd_p->pPhysCmdBuf +
			sizeof(HostCmd_FW_CORE_DUMP) -
			sizeof(HostCmd_FW_CORE_DUMP_);
		//(UINT32)virt_to_phys((const volatile void *)pCmd->Buffer);
		pCmd->cmd_data.coredump.buffer_len =
			ENDIAN_SWAP32(MAX_CORE_DUMP_BUFFER);
		pCmd->cmd_data.coredump.sizeB = ENDIAN_SWAP32(core_dump->sizeB);
		pCmd->cmd_data.coredump.flags = ENDIAN_SWAP32(core_dump->flags);

		//printk("\ncoredump->context=0x%x, coredump->buffer=0x%x, coredump->buffer_len=0x%x, coredump->sizeB=0x%x\n",
		//          pCmd->cmd_data.coredump.context, pCmd->cmd_data.coredump.buffer, pCmd->cmd_data.coredump.buffer_len, pCmd->cmd_data.coredump.sizeB);

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_CORE_DUMP));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_FW_CORE_DUMP);
		if (retval == SUCCESS) {
			retval = (ENDIAN_SWAP16(pCmd->CmdHdr.Result) ==
				  HostCmd_RESULT_OK) ? SUCCESS : FAIL;
			/*Update Core Dump Buffer */
			core_dump->context =
				ENDIAN_SWAP32(pCmd->cmd_data.coredump.context);
			core_dump->flags =
				ENDIAN_SWAP32(pCmd->cmd_data.coredump.flags);
			core_dump->sizeB =
				ENDIAN_SWAP32(pCmd->cmd_data.coredump.sizeB);
#ifdef SOC_W906X
			memcpy(buff, pCmd->Buffer, MAX_CORE_DUMP_BUFFER);
#else
			memcpy(buff,
			       (const void *)((UINT32) pCmd +
					      sizeof(HostCmd_FW_CORE_DUMP) -
					      sizeof(HostCmd_FW_CORE_DUMP_)),
			       MAX_CORE_DUMP_BUFFER);
#endif
		} else {
			printk("Fail to get coredump: cmd:0x%x %s\n",
			       HostCmd_CMD_GET_FW_CORE_DUMP,
			       ((retval == TIMEOUT) ? "TIMEOUT" : "FAIL"));
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwDiagMode(struct net_device *netdev, UINT16 status) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_DIAG_MODE *pCmd =
			(HostCmd_FW_DIAG_MODE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_DIAG_MODE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_CORE_DUMP_DIAG_MODE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_DIAG_MODE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Status = ENDIAN_SWAP16(status);
		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_DIAG_MODE));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_CORE_DUMP_DIAG_MODE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

#ifdef SOC_W906X
	int wlFwTxDropMode(struct net_device *netdev, UINT32 id, UINT16 flag,
			   UINT16 enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_DEBUG_TXDROP_MODE *pCmd =
			(HostCmd_DEBUG_TXDROP_MODE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_DEBUG_TXDROP_MODE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_TXDROP);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_DEBUG_TXDROP_MODE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Flag = ENDIAN_SWAP16(flag);
		pCmd->Enable = ENDIAN_SWAP16(enable);
		pCmd->id = ENDIAN_SWAP32(id);
		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_DEBUG_TXDROP_MODE));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_TXDROP);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFw_SetFixedPe(struct net_device *netdev, UINT8 pe, UINT16 enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_FIXED_PE *pCmd =
			(HostCmd_FW_FIXED_PE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_FIXED_PE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_FIXED_PE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_FIXED_PE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->enabled = enable;
		pCmd->pe = pe;

		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_FIXED_PE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
#endif

#ifdef NEW_DP
	int wlFwNewDP_Cmd(struct net_device *netdev, UINT8 ch, UINT8 width,
			  UINT8 rates, UINT8 rate_type, UINT8 rate_bw,
			  UINT8 rate_gi, UINT8 rate_ss)
	{

		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_CTRL *pCmd =
			(HostCmd_FW_NEWDP_CTRL *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_CTRL));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_CTRL);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_CTRL));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->ch = ch;
		pCmd->width = width;
		pCmd->rates = rates;
		pCmd->rate_type = rate_type;
		pCmd->rate_bw = rate_bw;
		pCmd->rate_gi = rate_gi;
		pCmd->rate_ss = rate_ss;

		retval = wlexecuteCommand(netdev, HostCmd_CMD_NEWDP_CTRL);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwNewDP_RateDrop(struct net_device *netdev, UINT32 enabled,
			       UINT32 rate_index, UINT32 staidx)
	{

		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_RATEDROP *pCmd =
			(HostCmd_FW_NEWDP_RATEDROP *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_RATEDROP));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_RATEDROP);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_RATEDROP));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
#ifdef CONFIG_MC_BC_RATE
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
#endif
		pCmd->enabled = enabled;
		pCmd->rate_index = ENDIAN_SWAP32(rate_index);
		pCmd->sta_index = ENDIAN_SWAP32(staidx);

		retval = wlexecuteCommand(netdev, HostCmd_CMD_NEWDP_RATEDROP);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	static inline void COPY_MAC_ADDR(u_int8_t * dst, u_int8_t * src) {
		(*(u_int16_t *) & dst[0]) = (*(u_int16_t *) & src[0]);
		(*(u_int16_t *) & dst[2]) = (*(u_int16_t *) & src[2]);
		(*(u_int16_t *) & dst[4]) = (*(u_int16_t *) & src[4]);
	}
	struct ieee80211_frame {
		IEEEtypes_FrameCtl_t FrmCtl;
		UINT8 dur[2];
		UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
		UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
		UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
		UINT8 seq[2];
		UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
	} PACK;

#ifdef SOC_W906X
//Extract from host driver's mwl_config_set_channel()
	u32 getChanExtOffset(u32 chan_num) {
		u32 ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

		switch (chan_num) {
		case 1:
		case 2:
		case 3:
		case 4:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 5:	/* AutoBW: for CH5 let it be CH5-10, rather than CH5-1 */
			/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
		case 6:	/* AutoBW: for CH6 let it be CH6-2, rather than CH6-10 */
		case 7:	/* AutoBW: for CH7 let it be CH7-3, rather than CH7-11 */
		case 8:
		case 9:
		case 10:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 11:
		case 12:
		case 13:
		case 14:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
			/* for 5G */
		case 36:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 40:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 44:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 48:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 52:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 56:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 60:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 64:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;

		case 100:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 104:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 108:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 112:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 116:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 120:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 124:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 128:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 132:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 136:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 140:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 144:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 149:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 153:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 157:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 161:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 165:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 169:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 173:
			ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 177:
			ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 181:
			ExtChnlOffset = NO_EXT_CHANNEL;
			break;
		}

		return ExtChnlOffset;
	}

// Calculate primary/sub from chan_num and width
#define HAL_CHANWIDTH_20MHZ 0
#define HAL_CHANWIDTH_40MHZ 1
#define HAL_CHANWIDTH_10MHZ 2
#define HAL_CHANWIDTH_5MHZ  3
#define HAL_CHANWIDTH_80MHZ 4
#define HAL_CHANWIDTH_160MHZ 5

#define HAL_ACTSUBCH_LOWER  0
#define HAL_ACTSUBCH_UPPER  1
#define HAL_ACTSUBCH_BOTH   2

	void getChanPrimarySub(u32 chan_num, u32 width, u32 * primary,
			       u32 * sub) {
		if (width == HAL_CHANWIDTH_20MHZ) {
			*primary = ACT_PRIMARY_CHAN_0;
			*sub = HAL_ACTSUBCH_LOWER;
		} else if (width == HAL_CHANWIDTH_40MHZ) {
			u32 ExtChnlOffset = getChanExtOffset(chan_num);

			if (ExtChnlOffset == EXT_CH_ABOVE_CTRL_CH) {
				*primary = ACT_PRIMARY_CHAN_0;
			} else if (ExtChnlOffset == EXT_CH_BELOW_CTRL_CH) {
				*primary = ACT_PRIMARY_CHAN_1;
			} else {
				*primary = ACT_PRIMARY_CHAN_0;
			}

			if (*primary & BIT(0)) {
				*sub = HAL_ACTSUBCH_LOWER;
			} else {
				*sub = HAL_ACTSUBCH_UPPER;
			}
		} else if (width == HAL_CHANWIDTH_80MHZ) {
			*primary =
				macMgmtMlme_Get80MHzPrimaryChannelOffset
				(chan_num);
			if (*primary & BIT(0)) {
				*sub = HAL_ACTSUBCH_LOWER;
			} else {
				*sub = HAL_ACTSUBCH_UPPER;
			}
		}

		return;
	}

	int wlFwOffChannel(struct net_device *netdev, u32 ch, u32 bw, u32 dwell,
			   u8 req_type, struct sk_buff *skb, u16 * result) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_OFFCHANNEL *pCmd =
			(HostCmd_FW_NEWDP_OFFCHANNEL *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		u32 primary = 0;
		u32 sub = 0;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		/* wlFwOffChannel() should only be called in OFFCHAN_IDLE state */
		if (wlpptr->offchan_state != OFFCHAN_IDLE) {
			retval = FAIL;
			*result = HostCmd_RESULT_OFFCHAN_IN_PROCESS;

			printk("wlFwOffChannel() err1, offchan_state = %d\n",
			       wlpptr->offchan_state);
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			WLDBG_EXIT(DBG_LEVEL_0);

			return retval;
		}

		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_OFFCHANNEL));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_OFFCHAN);

		if (skb != NULL)
			pCmd->CmdHdr.Length =
				ENDIAN_SWAP16(sizeof
					      (HostCmd_FW_NEWDP_OFFCHANNEL) -
					      (MAX_OFF_CHAN_PKT_SIZE -
					       skb->len));
		else
			pCmd->CmdHdr.Length =
				ENDIAN_SWAP16(sizeof
					      (HostCmd_FW_NEWDP_OFFCHANNEL) -
					      MAX_OFF_CHAN_PKT_SIZE);

		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->OffChannel.channel = ENDIAN_SWAP32(ch);
		pCmd->OffChannel.channel_width = ENDIAN_SWAP32(bw);
		pCmd->OffChannel.dwell_time = ENDIAN_SWAP32(dwell);
		pCmd->OffChannel.req_type = req_type;
		getChanPrimarySub(ch, bw, &primary, &sub);
		pCmd->OffChannel.primary = ENDIAN_SWAP32(primary);
		pCmd->OffChannel.sub = ENDIAN_SWAP32(sub);

		if ((pCmd->OffChannel.req_type == OFF_CHAN_REQ_TYPE_TX) &&
		    (skb != NULL))
			memcpy(&(pCmd->Data[0]), skb->data, skb->len);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_OFFCHANNEL));

		retval = wlexecuteCommand(netdev, HostCmd_CMD_OFFCHAN);
		if (retval != SUCCESS) {
			printk("wlFwOffChannel error\n");
			*result = 0xFFFF;
		} else
			*result = pCmd->CmdHdr.Result;

		//If there's something wrong when FW processes off-chan command, don't change the state. Remain at OFFCHAN_IDLE.
		if ((retval == SUCCESS) && (*result == HostCmd_RESULT_OK)) {
			wlpptr->offchan_state = OFFCHAN_STARTED;
			schedule_work(&wlpptr->wlpd_p->offchantask);
		} else {
#if 0
			//We borrow quiet's funciton to dis/enable TX traffic
			quiet_stop_allInf(netdev, FALSE);
#endif
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		WLDBG_EXIT(DBG_LEVEL_0);

		return retval;
	}

	int wlFwOffChannel_dbg(struct net_device *netdev,
			       u32 * fw_offchan_state) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_OFFCHANNEL_DBG *pCmd =
			(HostCmd_FW_NEWDP_OFFCHANNEL_DBG *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_DBG));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_OFFCHAN_DBG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_DBG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_DBG));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_OFFCHAN_DBG);
		if (retval != SUCCESS) {
			printk("wlFwOffChannel_dbg error\n");
			*fw_offchan_state = 0xFFFFFFFF;
		} else {
			*fw_offchan_state = pCmd->offchan_state;
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		WLDBG_EXIT(DBG_LEVEL_0);

		return retval;
	}
#endif

	int wlFwNewDP_OffChannel_Start(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_OFFCHANNEL_START *pCmd =
			(HostCmd_FW_NEWDP_OFFCHANNEL_START *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		//Just need to allocated once
		if (wlpptr->wlpd_p->descData[0].pOffChReqRing == NULL) {
#ifdef SOC_W906X
			wlpptr->wlpd_p->descData[0].pOffChReqRing = (u_int8_t *)
				wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
						      MAX_OFF_CHAN_REQ *
						      sizeof(offchan_desc_t),
						      &wlpptr->wlpd_p->
						      descData[0].
						      pPhysOffChReqRing,
						      wlpptr->wlpd_p->
						      dma_alloc_flags);

			wlpptr->wlpd_p->descData[0].pOffChDoneRing =
				(u_int8_t *)
				wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
						      MAX_OFF_CHAN_DONE *
						      sizeof
						      (offchan_done_stat_t),
						      &wlpptr->wlpd_p->
						      descData[0].
						      pPhysOffChDoneRing,
						      wlpptr->wlpd_p->
						      dma_alloc_flags);
#else
			wlpptr->wlpd_p->descData[0].pOffChReqRing =
				(u_int8_t *) pci_alloc_consistent(wlpptr->
								  pPciDev,
								  MAX_OFF_CHAN_REQ
								  *
								  sizeof
								  (offchan_desc_t),
								  &wlpptr->
								  wlpd_p->
								  descData[0].
								  pPhysOffChReqRing);

			wlpptr->wlpd_p->descData[0].pOffChDoneRing =
				(u_int8_t *) pci_alloc_consistent(wlpptr->
								  pPciDev,
								  MAX_OFF_CHAN_DONE
								  *
								  sizeof
								  (offchan_done_stat_t),
								  &wlpptr->
								  wlpd_p->
								  descData[0].
								  pPhysOffChDoneRing);
#endif
		}
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_START));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_OFFCHAN_START);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_NEWDP_OFFCHANNEL_START));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->OffChanReqBase =
			ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].
				      pPhysOffChReqRing);
		pCmd->OffChanDoneBase =
			ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].
				      pPhysOffChDoneRing);
		pCmd->pPhyoffchanshared =
			ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].
				      pPhyoffchanshared);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_START));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_OFFCHAN_START);
		if (retval == SUCCESS) {
			wlpptr->wlpd_p->descData[0].OffChanReqHead =
				ENDIAN_SWAP32(pCmd->OffChanReqHead);
			wlpptr->wlpd_p->descData[0].OffChanReqTail =
				ENDIAN_SWAP32(pCmd->OffChanReqTail);
			wlpptr->wlpd_p->descData[0].OffChanDoneHead =
				ENDIAN_SWAP32(pCmd->OffChanDoneHead);
			wlpptr->wlpd_p->descData[0].OffChanDoneTail =
				ENDIAN_SWAP32(pCmd->OffChanDoneTail);
			printk("OffChanReqHead = %x\nOffChanReqTail = %x\nOffChanDoneHead = %x\nOffChanDoneTail = %x\n", wlpptr->wlpd_p->descData[0].OffChanReqHead, wlpptr->wlpd_p->descData[0].OffChanReqTail, wlpptr->wlpd_p->descData[0].OffChanDoneHead, wlpptr->wlpd_p->descData[0].OffChanDoneTail);
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	BOOLEAN bReqTypeRx = FALSE;

#ifdef SOC_W906X
	int wlFwNewDP_queue_OffChan_req(struct net_device *netdev,
					DOT11_OFFCHAN_REQ_t * pOffChan) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		unsigned long flags;
		unsigned long listflags;
		offChanListItem *offChanListItem_p = NULL;
		offchan_desc_t *pOffChDesc;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		if (wlpptr->master) {
			printk("offchan only apply to physical interface...\n");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		//Check if interface is down. If down, do not accept new request
		if ((vmacSta_p->acs_mode != 1) &&
		    (netdev->flags & IFF_RUNNING) == 0) {
			printk("offchan interface is down\n");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		if (wlpptr->wlpd_p->offChanList.cnt > 1000) {
			/* allow only 1000 offch req */
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		if ((offChanListItem_p =
		     wl_kmalloc(sizeof(offChanListItem), GFP_ATOMIC)) == NULL) {
			printk("Cannot allocate memory for offChanListItem_p\n");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		//Clear the memory buffer
		memset(offChanListItem_p, 0, sizeof(offChanListItem));

		pOffChDesc = &(offChanListItem_p->offchan_desc);

		pOffChDesc->OffChannel.id = ENDIAN_SWAP32(pOffChan->id);
		pOffChDesc->OffChannel.channel =
			ENDIAN_SWAP32(pOffChan->channel);
		pOffChDesc->OffChannel.lifetime =
			ENDIAN_SWAP32(pOffChan->lifetime);
		pOffChDesc->OffChannel.start_ts =
			ENDIAN_SWAP32(pOffChan->start_ts);
		pOffChDesc->OffChannel.dwell_time =
			ENDIAN_SWAP32(pOffChan->dwell_time);
		pOffChDesc->OffChannel.channel_width =
			ENDIAN_SWAP32(pOffChan->channel_width);
		pOffChDesc->OffChannel.radio_slot = pOffChan->radio_slot;
		pOffChDesc->OffChannel.req_type = pOffChan->req_type;
		if (pOffChan->req_type == 0) {
			bReqTypeRx = TRUE;
		} else {
			bReqTypeRx = FALSE;
		}
		pOffChDesc->OffChannel.priority = pOffChan->priority;
		pOffChDesc->OffChannel.status = pOffChan->status;

		if (pOffChan->pak != NULL) {
			struct sk_buff *txSkb_p = NULL;
			struct ieee80211_frame *pWHdr;
			UINT16 MrvlFrmLen;
			int retval;
			IEEEtypes_GenHdr_t *pHdr =
				(IEEEtypes_GenHdr_t *) pOffChan->pak;

			MrvlFrmLen = pHdr->FrmBodyLen + 2;

			txSkb_p = wl_alloc_skb(MrvlFrmLen + 64);
			if (txSkb_p == NULL) {
				printk("Cannot allocate memory for txSkb_p\n");
				if (offChanListItem_p) {
					wl_kfree(offChanListItem_p);
				}
				MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
				return FAIL;
			}

			offChanListItem_p->txSkb_p = txSkb_p;

			retval = copy_from_user(txSkb_p->data, pOffChan->pak,
						MrvlFrmLen);

			skb_put(txSkb_p, MrvlFrmLen);
			pWHdr = (struct ieee80211_frame *)&txSkb_p->data[2];

#if 0
			COPY_MAC_ADDR(pOffChDesc->txDesc.u.DA, pWHdr->addr1);
			COPY_MAC_ADDR(pOffChDesc->txDesc.u.SA, pWHdr->addr2);
			pOffChDesc->txDesc.Data =
				dma_map_single(wlpptr->wlpd_p->dev,
					       txSkb_p->data, txSkb_p->len,
					       DMA_TO_DEVICE);
#endif
#if 0
			printk("pOffChDesc->txDesc.Data = 0x%x, txSkb_p->len = %d\n", pOffChDesc->txDesc.Data, txSkb_p->len);
			if (txSkb_p->len >= 8) {
				printk("data[0][1][2][3]/[%d][%d][%d][%d] = %x %x %x %x %x %x %x %x\n", txSkb_p->len - 4, txSkb_p->len - 3, txSkb_p->len - 2, txSkb_p->len - 1, txSkb_p->data[0], txSkb_p->data[1], txSkb_p->data[2], txSkb_p->data[3], txSkb_p->data[txSkb_p->len - 4], txSkb_p->data[txSkb_p->len - 3], txSkb_p->data[txSkb_p->len - 2], txSkb_p->data[txSkb_p->len - 1]);
			}
#endif
			/* TODO. Do we need off channel? Change to new TX descriptor. */
#if 0
			pOffChDesc->txDesc.Ctrl =
				ENDIAN_SWAP32(((0 & txring_Ctrl_QIDmask) <<
					       txring_Ctrl_QIDshift) |
					      (((txSkb_p->len -
						 (sizeof
						  (struct ieee80211_frame)) -
						 2) & txring_Ctrl_LenMask) <<
					       txring_Ctrl_LenShift) |
					      (txring_Ctrl_TAG_MGMT <<
					       txring_Ctrl_TAGshift));
#endif
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.offChanListLock,
				  listflags);
		ListPutItem(&wlpptr->wlpd_p->offChanList,
			    (ListItem *) offChanListItem_p);
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanListLock,
				       listflags);

		//Only notify offchantask when it's currently IDLE.
		//If offchan is at another state, the state machine will check offChanList when it goes back to IDLE.
		if (wlpptr->offchan_state == OFFCHAN_IDLE) {
			schedule_work(&wlpptr->wlpd_p->offchantask);
		}

		return SUCCESS;
	}
#else //906X off-channel
	int wlFwNewDP_queue_OffChan_req(struct net_device *netdev,
					DOT11_OFFCHAN_REQ_t * pOffChan) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		unsigned long flags;
		unsigned long listflags;
		struct sk_buff *txSkb_p = NULL;
		struct ieee80211_frame *pWHdr;
		UINT16 MrvlFrmLen;
		ReqIdListItem *ReqIdListItem_p = NULL;
		UINT32 offchReqHead;
		UINT32 offchReqTail;
		UINT32 nextOff;
		offchan_desc_t *pOffChDesc;
		int retval;
#ifdef SOC_W906X
		unsigned int reg_offchreq_head =
			wlpptr->wlpd_p->reg.offch_req_head;
		unsigned int reg_offchreq_tail =
			wlpptr->wlpd_p->reg.offch_req_tail;
#endif

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
#ifdef SOC_W906X
		offchReqHead = wl_util_readl(netdev, wlpptr->ioBase1 + reg_offchreq_head);
		offchReqTail = wl_util_readl(netdev, wlpptr->ioBase1 + reg_offchreq_tail);
#else
		offchReqHead = wl_util_readl(netdev, wlpptr->ioBase1 + MACREG_REG_OffchReqHead);
		offchReqTail = wl_util_readl(netdev, wlpptr->ioBase1 + MACREG_REG_OffchReqTail);
#endif
		nextOff = offchReqHead * sizeof(offchan_desc_t);
		pOffChDesc =
			(offchan_desc_t *) (wlpptr->wlpd_p->descData[0].
					    pOffChReqRing + nextOff);

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		if (((offchReqHead + 1) % MAX_OFF_CHAN_REQ) == offchReqTail) {
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		pOffChDesc->OffChannel.id = ENDIAN_SWAP32(pOffChan->id);
		pOffChDesc->OffChannel.channel =
			ENDIAN_SWAP32(pOffChan->channel);
		pOffChDesc->OffChannel.lifetime =
			ENDIAN_SWAP32(pOffChan->lifetime);
		pOffChDesc->OffChannel.start_ts =
			ENDIAN_SWAP32(pOffChan->start_ts);
		pOffChDesc->OffChannel.dwell_time =
			ENDIAN_SWAP32(pOffChan->dwell_time);
		pOffChDesc->OffChannel.channel_width =
			ENDIAN_SWAP32(pOffChan->channel_width);
		pOffChDesc->OffChannel.radio_slot = pOffChan->radio_slot;
		pOffChDesc->OffChannel.req_type = pOffChan->req_type;
		if (pOffChan->req_type == 0) {
			bReqTypeRx = TRUE;
		} else {
			bReqTypeRx = FALSE;
		}
		pOffChDesc->OffChannel.priority = pOffChan->priority;
		pOffChDesc->OffChannel.status = pOffChan->status;

		if (pOffChan->pak != NULL) {
			IEEEtypes_GenHdr_t *pHdr =
				(IEEEtypes_GenHdr_t *) pOffChan->pak;

			MrvlFrmLen = pHdr->FrmBodyLen + 2;

			txSkb_p = wl_alloc_skb(MrvlFrmLen + 64);
			if (txSkb_p == NULL) {
				printk("Cannot allocate memory for txSkb_p\n");
				MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
				return FAIL;
			}
			retval = copy_from_user(txSkb_p->data, pOffChan->pak,
						MrvlFrmLen);
			skb_put(txSkb_p, MrvlFrmLen);
			pWHdr = (struct ieee80211_frame *)&txSkb_p->data[2];

			COPY_MAC_ADDR(pOffChDesc->txDesc.u.DA, pWHdr->addr1);
			COPY_MAC_ADDR(pOffChDesc->txDesc.u.SA, pWHdr->addr2);
#ifdef SOC_W906X
			pOffChDesc->txDesc.Data =
				dma_map_single(wlpptr->wlpd_p->dev,
					       txSkb_p->data, txSkb_p->len,
					       DMA_TO_DEVICE);

			/* TODO. Do we need off channel? Change to new TX descriptor. */
#if 0
			pOffChDesc->txDesc.Ctrl =
				ENDIAN_SWAP32(((0 & txring_Ctrl_QIDmask) <<
					       txring_Ctrl_QIDshift) |
					      (((txSkb_p->len -
						 (sizeof
						  (struct ieee80211_frame)) -
						 2) & txring_Ctrl_LenMask) <<
					       txring_Ctrl_LenShift) |
					      (txring_Ctrl_TAG_MGMT <<
					       txring_Ctrl_TAGshift));
#endif
#else
			pOffChDesc->txDesc.Data =
				ENDIAN_SWAP32(pci_map_single
					      (wlpptr->pPciDev, txSkb_p->data,
					       txSkb_p->len, PCI_DMA_TODEVICE));
			pOffChDesc->txDesc.Ctrl =
				ENDIAN_SWAP32(((0 & txring_Ctrl_QIDmask) <<
					       txring_Ctrl_QIDshift) |
					      (((txSkb_p->len -
						 (sizeof
						  (struct ieee80211_frame)) -
						 2) & txring_Ctrl_LenMask) <<
					       txring_Ctrl_LenShift) |
					      (txring_Ctrl_TAG_MGMT <<
					       txring_Ctrl_TAGshift));
#endif /* #ifdef SOC_W906X */
		}
		if ((ReqIdListItem_p =
		     wl_kmalloc(sizeof(ReqIdListItem), GFP_ATOMIC)) == NULL) {
			if (txSkb_p)
				wl_free_skb(txSkb_p);
			printk("Cannot allocate memory for ReqId list item\n");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		ReqIdListItem_p->ReqId = pOffChan->id;
		ReqIdListItem_p->txSkb_p = txSkb_p;
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock,
				  listflags);
		ListPutItem(&wlpptr->wlpd_p->ReqIdList,
			    (ListItem *) ReqIdListItem_p);
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock,
				       listflags);
		if ((offchReqHead + 1) == MAX_OFF_CHAN_REQ)
			offchReqHead = 0;
		else
			offchReqHead++;
#ifdef SOC_W906X
		wl_util_writel(netdev, offchReqHead, wlpptr->ioBase1 + reg_offchreq_head);
#else
		wl_util_writel(netdev, offchReqHead, wlpptr->ioBase1 + MACREG_REG_OffchReqHead);
#endif
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return SUCCESS;
	}
#endif //906X off-channel
	BOOLEAN bStartOffChanRx = FALSE;
	extern UINT32 OffChanRxCnt;

#ifdef SOC_W906X
	offChanListItem *offchan_current_req_p = NULL;
#define OFFCHAN_COOLDOWN_TIME	2	//in 100ms unit. 10 = 1sec

	static void offChanCooldown_cb(void *data_p) {
		struct net_device *netdev = (struct net_device *)data_p;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		WLDBG_INFO(DBG_LEVEL_1, "offChanCooldownHdlr\n");

		//1. Change offchan_state to IDLE
		wlpptr->offchan_state = OFFCHAN_IDLE;

		//2. Trigger offchantask to check next request
		schedule_work(&wlpptr->wlpd_p->offchantask);

		return;
	}

	extern SINT32 syncSrv_ScanActTimeOut(UINT8 * data);
	static unsigned int acs_data[14][18];
	int wlFwNewDP_handle_OffChan_event(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		offChanListItem *offChanListItem_p = NULL;
		unsigned long listflags;
		int ret;
		u16 result;

		switch (wlpptr->offchan_state) {
		case OFFCHAN_IDLE:
			{
				//Check if interface is down. If down, do nothing and remain at idle state
				if ((vmacSta_p->acs_mode != 1) &&
				    (netdev->flags & IFF_RUNNING) == 0) {
					break;
				}
				//Check if there is pending off-chan req. If yes, deliver the next off-chan req to FW.
				SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.
						  offChanListLock, listflags);
				offChanListItem_p =
					(offChanListItem *)
					ListGetItem(&wlpptr->wlpd_p->
						    offChanList);
				SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.
						       offChanListLock,
						       listflags);

				if (offChanListItem_p != NULL) {
					//Save the offChanListItem. Will free it when OFFCHAN_DONE.
					offchan_current_req_p =
						offChanListItem_p;
					switch (offchan_current_req_p->
						offchan_desc.OffChannel.
						req_type) {
					case OFFCHAN_TYPE_RX:
					case OFFCHAN_TYPE_TX:
					case OFFCHAN_TYPE_RX_NF:
						{
							//Copy from setcmd "offchan"
							u32 ch = offchan_current_req_p->offchan_desc.OffChannel.channel;
							u32 bw = offchan_current_req_p->offchan_desc.OffChannel.channel_width;
							u32 dwell =
								offchan_current_req_p->
								offchan_desc.
								OffChannel.
								dwell_time;
							u8 req_type =
								offchan_current_req_p->
								offchan_desc.
								OffChannel.
								req_type;

							ret = wlFwOffChannel
								(netdev, ch, bw,
								 dwell,
								 req_type,
								 offchan_current_req_p->
								 txSkb_p,
								 &result);
							if (ret == SUCCESS) {
								switch (result) {
								case HostCmd_RESULT_OFFCHAN_BCN_GUARD:
									{
										ret = wlFwOffChannel(netdev, ch, bw, dwell, req_type, offchan_current_req_p->txSkb_p, &result);
										if ((ret != SUCCESS) || (result != HostCmd_RESULT_OK)) {
											printk("Offchan failed again, %d / %d\n", ret, result);
										}
										break;
									}
								case HostCmd_RESULT_OFFCHAN_IN_PROCESS:
									{
										printk("HostCmd_RESULT_OFFCHAN_IN_PROCESS, this request is canceled\n");
										break;
									}
								default:
									{
										break;
									}
								}
							}

							break;
						}
					default:
						{
							printk("wlFwNewDP_handle_OffChan_event(), un-supported req_type = %d\n", offchan_current_req_p->offchan_desc.OffChannel.req_type);
							break;
						}
					}

					//Current state should be changed to OFFCHAN_STARTED now unless we encounter any problem.
					//If any problem, go to DONE state immediately.
					//Therefore, the req/packet will be freed, and the cooldown timer will be triggered.
					if (wlpptr->offchan_state ==
					    OFFCHAN_IDLE) {
						//printk("goto OFFCHAN_PROCESS_FAIL\n");
						goto OFFCHAN_PROCESS_FAIL;
					}
				}
				break;
			}
		case OFFCHAN_STARTED:
			{
				//Do nothing, wait for OFFCHAN_CH_CHANGE event
				break;
			}
		case OFFCHAN_CH_CHANGE:
			{
				//1. Copy the followings from SC4 driver
				bStartOffChanRx = TRUE;
				break;
			}
		case OFFCHAN_DONE:
			{
				SINT32 i;
				mvl_status_t tmp_status;
				extern mvl_status_t
					CH_radio_status[IEEEtypes_MAX_CHANNELS +
							IEEEtypes_MAX_CHANNELS_A];

OFFCHAN_PROCESS_FAIL:
				//1. Free the current offChanListItem
				if (offchan_current_req_p != NULL) {
					if (offchan_current_req_p->txSkb_p !=
					    NULL)
						wl_free_skb
							(offchan_current_req_p->
							 txSkb_p);
					wl_kfree(offchan_current_req_p);
					offchan_current_req_p = NULL;
				} else {
					printk("wlFwNewDP_handle_OffChan_event(), offchan_current_req_p = NULL\n");
				}
				//2. Trigger a timer for cooldown
				TimerFireIn(&wlpptr->wlpd_p->
					    offChanCooldownTimer, 1,
					    &offChanCooldown_cb, (void *)netdev,
					    OFFCHAN_COOLDOWN_TIME);
				//3. Set to OFFCHAN_COOLDOWN state
				wlpptr->offchan_state = OFFCHAN_COOLDOWN;
				//4. Copy the followings from SC4 driver
				bStartOffChanRx = FALSE;
#ifdef IEEE80211K
				MSAN_update_neighbor_list(netdev);
#endif
				MSAN_unassocsta_offchan_done(netdev,
							     UNASSOCSTA_TRACK_MODE_OFFCHAN);

				memset(&tmp_status, 0, sizeof(mvl_status_t));
				wlFwGetRadioStatus(netdev, &tmp_status);
				i = GetRegionChanIndx(GetDomainIndxIEEERegion
						      (domainGetDomain()),
						      tmp_status.channel);
				if (i <
				    IEEEtypes_MAX_CHANNELS +
				    IEEEtypes_MAX_CHANNELS_A) {
					memcpy(&CH_radio_status[i], &tmp_status,
					       sizeof(mvl_status_t));
				}

				{
					char *string_buff =
						NULL,
						tmp_buff[ACNT_MAX_STR_LEN];
					UINT8 *filename = "/tmp/acs_data.txt";
					struct file *filp_acs_data = NULL;
					u8 i = 0;

					if ((string_buff =
					     (char *)wl_kmalloc_autogfp(4096))
					    == NULL) {
						break;
					}

					if ((tmp_status.channel > 0) &&
					    (tmp_status.channel < 14)) {
						for (i = 0; i < 18; i++) {
							acs_data[tmp_status.
								 channel -
								 1][i] =
								tmp_status.
								nf_dbm[i];
						}
					}

					for (i = 0; i < 14; i++) {
						memset(tmp_buff, 0,
						       sizeof(tmp_buff));
						sprintf(tmp_buff,
							"%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
							acs_data[i][0],
							acs_data[i][1],
							acs_data[i][2],
							acs_data[i][3],
							acs_data[i][4],
							acs_data[i][5],
							acs_data[i][6],
							acs_data[i][7],
							acs_data[i][8],
							acs_data[i][9],
							acs_data[i][10],
							acs_data[i][11],
							acs_data[i][12],
							acs_data[i][13],
							acs_data[i][14],
							acs_data[i][15],
							acs_data[i][16],
							acs_data[i][17]);
						strcat(string_buff, tmp_buff);
					}

					filp_acs_data =
						filp_open(filename,
							  O_RDWR | O_CREAT |
							  O_TRUNC, 0);
					if (!IS_ERR(filp_acs_data)) {
						__kernel_write(filp_acs_data,
							       string_buff,
							       strlen
							       (string_buff),
							       &filp_acs_data->
							       f_pos);
						filp_close(filp_acs_data,
							   current->files);
					}

					wl_kfree(string_buff);
				}

				/* if ACS mode is NF-reading and auto channel process is on-going, call timeout */
				if (*(vmacSta_p->Mib802dot11->mib_autochannel)
				    && (vmacSta_p->preautochannelfinished == 0)
				    && (vmacSta_p->acs_mode == 1)) {
					memcpy(vmacSta_p->
					       acs_db[vmacSta_p->ChanIdx].
					       nf_bin, tmp_status.nf_dbm,
					       MAX_NF_DBM_LEN * sizeof(u32));
					syncSrv_ScanActTimeOut((UINT8 *)
							       vmacSta_p);
				}

				break;
			}
		case OFFCHAN_COOLDOWN:
			break;

		default:
			break;
		}

		return SUCCESS;
	}
#else //906X off-channel
	extern BOOLEAN bReqTypeRx;
	int wlFwNewDP_handle_OffChan_event(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		UINT32 offchDoneHead =
			((offchan_shared_t *) wlpptr->wlpd_p->descData[0].
			 poffchanshared)->OffChanDoneHead;
		UINT32 offchDoneTail =
			((offchan_shared_t *) wlpptr->wlpd_p->descData[0].
			 poffchanshared)->OffChanDoneTail;
		offchan_done_stat_t *pOffDone, *pOffHead;
		char evBuf[64];
		ReqIdListItem *ReqIdListItem_p = NULL;
		unsigned long listflags;
		UINT32 listcnt = 0;

		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock,
				  listflags);

		while (offchDoneHead != offchDoneTail) {
			pOffDone =
				(offchan_done_stat_t *) (wlpptr->wlpd_p->
							 descData[0].
							 pOffChDoneRing +
							 offchDoneTail *
							 sizeof
							 (offchan_done_stat_t));
			pOffHead =
				(offchan_done_stat_t *) (wlpptr->wlpd_p->
							 descData[0].
							 pOffChDoneRing +
							 offchDoneHead *
							 sizeof
							 (offchan_done_stat_t));

			if ((ENDIAN_SWAP32(pOffDone->status) ==
			     OFFCHAN_CH_CHANGE) && bReqTypeRx) {
				bStartOffChanRx = TRUE;
			} else if (ENDIAN_SWAP32(pOffDone->status) ==
				   OFFCHAN_DONE) {
				bStartOffChanRx = FALSE;
#ifdef IEEE80211K
				MSAN_update_neighbor_list(netdev);
#endif
			}

			if ((ENDIAN_SWAP32(pOffDone->status) == OFFCHAN_DONE) ||
			    (ENDIAN_SWAP32(pOffDone->status) == OFFCHAN_FAIL)) {
				while ((ReqIdListItem_p =
					(ReqIdListItem *) ListGetItem(&wlpptr->
								      wlpd_p->
								      ReqIdList))
				       != NULL) {
					if (ReqIdListItem_p->ReqId ==
					    ENDIAN_SWAP32(pOffDone->id)) {
						if (ReqIdListItem_p->txSkb_p !=
						    NULL)
							wl_free_skb
								(ReqIdListItem_p->
								 txSkb_p);
						wl_kfree(ReqIdListItem_p);
						break;
					} else {
						/* Put it back */
						ListPutItem(&wlpptr->wlpd_p->
							    ReqIdList,
							    (ListItem *)
							    ReqIdListItem_p);
					}

					/*To prevent going into infinite loop when tail status is 1 and id doesn't match with any in ReqIdList */
					listcnt++;
					if (listcnt >
					    wlpptr->wlpd_p->ReqIdList.cnt) {
						//printk("listcnt %d > cnt %d\n", listcnt, wlpptr->wlpd_p->ReqIdList.cnt);
						break;
					}

				}
			}

			sprintf(evBuf, "off-channel-status %d %d\n",
				ENDIAN_SWAP32(pOffDone->id),
				ENDIAN_SWAP32(pOffDone->status));
			WLSNDEVT(netdev, IWEVCUSTOM,
				 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.
				 macAddr[0], evBuf);

			if ((offchDoneTail + 1) == MAX_OFF_CHAN_DONE)
				offchDoneTail = 0;
			else
				offchDoneTail++;
		}
		((offchan_shared_t *) wlpptr->wlpd_p->descData[0].
		 poffchanshared)->OffChanDoneTail = offchDoneTail;

		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock,
				       listflags);

		return SUCCESS;
	}
#endif

	int wlFwNewDP_config_prom(struct net_device *netdev,
				  PROM_CNF_t * PromCnf) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef SOC_W906X
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		int retval = SUCCESS;
		U32 op_mode = SMAC_OPMODE_NORMAL;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		if (PromCnf->PromDataMask)
			op_mode = SMAC_OPMODE_PROMISC_DATA;

		if (PromCnf->PromMgmtMask)
			op_mode |= SMAC_OPMODE_PROMISC_MGMT;

		if (PromCnf->PromCtrlMask)
			op_mode |= SMAC_OPMODE_PROMISC_CTRL;

		if (op_mode != SMAC_OPMODE_NORMAL) {
			U32 regval;

			wl_util_lock(netdev);
			op_mode |= SMAC_OPMODE_FCS_ERR_PASS;
			*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->
				  config.opMode) = op_mode;
			wl_util_unlock(netdev);
			SMAC_RX_ENABLE(wlpptr, mib, 0xFFFFFFFF);
			regval = wl_util_readl(netdev, wlpptr->ioBase1 + BBRX_CFG);
			if ((regval & 0x01) == 0)
				wl_util_writel(netdev, (regval | 0x01), wlpptr->ioBase1 + BBRX_CFG);
		} else {
			wl_util_lock(netdev);
			*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->
				  config.opMode) = op_mode;
			wl_util_unlock(netdev);
			SMAC_RX_DISABLE(wlpptr, mib, 0xFFFFFFFF);
		}
#else
		HostCmd_FW_NEWDP_PROM_CNF *pCmd =
			(HostCmd_FW_NEWDP_PROM_CNF *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_PROM_CNF));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_CONFIG_PROM);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_PROM_CNF));
		pCmd->PromCnf.CnfType = PromCnf->CnfType;
		pCmd->PromCnf.PromDataMask =
			ENDIAN_SWAP16(PromCnf->PromDataMask);
		pCmd->PromCnf.PromDataTrunc =
			ENDIAN_SWAP16(PromCnf->PromDataTrunc);
		pCmd->PromCnf.PromMgmtMask =
			ENDIAN_SWAP16(PromCnf->PromMgmtMask);
		pCmd->PromCnf.PromMgmtTrunc =
			ENDIAN_SWAP16(PromCnf->PromMgmtTrunc);
		pCmd->PromCnf.PromCtrlMask =
			ENDIAN_SWAP16(PromCnf->PromCtrlMask);
		pCmd->PromCnf.PromCtrlTrunc =
			ENDIAN_SWAP16(PromCnf->PromCtrlTrunc);
		pCmd->PromCnf.PromRsvdMask =
			ENDIAN_SWAP16(PromCnf->PromRsvdMask);
		pCmd->PromCnf.PromRsvdTrunc =
			ENDIAN_SWAP16(PromCnf->PromRsvdTrunc);
		pCmd->PromCnf.PromPolNomWin =
			ENDIAN_SWAP32(PromCnf->PromPolNomWin);
		pCmd->PromCnf.PromPolNomPkts =
			ENDIAN_SWAP32(PromCnf->PromPolNomPkts);

		printk("CnfType =%d\n", pCmd->PromCnf.CnfType);
		printk("PromDataMask =%d\n", pCmd->PromCnf.PromDataMask);
		printk("PromDataTrunc =%d\n", pCmd->PromCnf.PromDataTrunc);
		printk("PromMgmtMask =%d\n", pCmd->PromCnf.PromMgmtMask);
		printk("PromMgmtTrunc =%d\n", pCmd->PromCnf.PromMgmtTrunc);
		printk("PromCtrlMask =%d\n", pCmd->PromCnf.PromCtrlMask);
		printk("PromCtrlTrunc =%d\n", pCmd->PromCnf.PromCtrlTrunc);
		printk("PromRsvdMask =%d\n", pCmd->PromCnf.PromRsvdMask);
		printk("PromRsvdTrunc =%d\n", pCmd->PromCnf.PromRsvdTrunc);
		printk("PromPolNomWin =%d\n", pCmd->PromCnf.PromPolNomWin);
		printk("PromPolNomPkts =%d\n", pCmd->PromCnf.PromPolNomPkts);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_PROM_CNF));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_CONFIG_PROM);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
#endif /* #ifdef SOC_W906X */
		return retval;

	}

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	int wlFwNewDP_setAcntBufSize(struct net_device *netdev,
				     u_int32_t * base, u_int32_t size,
				     u_int32_t ActionType)
#else
	int wlFwNewDP_setAcntBufSize(struct net_device *netdev, u_int32_t base,
				     u_int32_t size)
#endif
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_ACNT_BUF_SIZE *pCmd =
			(HostCmd_FW_SET_ACNT_BUF_SIZE *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
		UINT8 i;
		UINT32 chunksize, log2 = 0;
#endif

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_ACNT_BUF_SIZE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_SET_ACNT_BUF_SIZE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_ACNT_BUF_SIZE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
		pCmd->Action = ENDIAN_SWAP32(ActionType);
		//printk("action type = %d\n", ActionType);
		if (ActionType == ACNT_SET_BUF) {
			chunksize = size / ACNT_NCHUNK;
			while (chunksize >>= 1)
				log2++;	//calculate log2 of chunk size

			pCmd->log2Chunk = ENDIAN_SWAP32(log2);
			//printk("log2chunk size %d\n", log2);
			for (i = 0; i < ACNT_NCHUNK; i++) {
				pCmd->acntBufBase[i] = ENDIAN_SWAP32(base[i]);
			}

		}
#else
		pCmd->acntBufBase = ENDIAN_SWAP32(base);
#endif

		pCmd->acntBufSize = ENDIAN_SWAP32(size);
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_PROM_CNF));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_SET_ACNT_BUF_SIZE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;

	}
	int wlFwNewDP_sensorD_init(struct net_device *netdev,
				   sensord_init_t * sensordinit, UINT8 action) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_NEWDP_SENSORD_INIT *pCmd =
			(HostCmd_FW_NEWDP_SENSORD_INIT *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_SENSORD_INIT));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_SENSORD_INIT);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_SENSORD_INIT));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		if (action) {
			pCmd->SensordInit_ext.mrvl_pri_mailbox =
				(UINT32) ENDIAN_SWAP32((UINT32) wlpptr->wlpd_p->
						       MrvlPriSharedMem.
						       dataPhysicalLoc);
			pCmd->SensordInit_ext.SensordInit.ca_mailbox =
				(UINT32) ENDIAN_SWAP32((UINT32) wlpptr->wlpd_p->
						       AllocSharedMeminfo.
						       dataPhysicalLoc);
			pCmd->SensordInit_ext.SensordInit.buff_size =
				ENDIAN_SWAP32(sensordinit->buff_size);
			pCmd->SensordInit_ext.SensordInit.num_freq =
				ENDIAN_SWAP32(sensordinit->num_freq);
			pCmd->SensordInit_ext.SensordInit.instance =
				ENDIAN_SWAP32(sensordinit->instance);
			pCmd->SensordInit_ext.SensordInit.mvl_radio_id =
				ENDIAN_SWAP32(sensordinit->mvl_radio_id);
			pCmd->SensordInit_ext.SensordInit.enableSI =
				sensordinit->enableSI;
			memcpy(pCmd->SensordInit_ext.SensordInit.nsiKey,
			       sensordinit->nsiKey, SENSORD_NSIKEY_LEN);
		} else {
			pCmd->SensordInit_ext.mrvl_pri_mailbox =
				(UINT32) ENDIAN_SWAP32((UINT32) wlpptr->wlpd_p->
						       MrvlPriSharedMem.
						       dataPhysicalLoc);
			pCmd->SensordInit_ext.SensordInit.ca_mailbox =
				(UINT32) ENDIAN_SWAP32((UINT32) wlpptr->wlpd_p->
						       AllocSharedMeminfo.
						       dataPhysicalLoc);
		}

		pCmd->Action = action;	//0: To pass only shared mem to fw , 1: to pass sensord param and shared mem

		//pCmd->SensordInit_ext.SensordInit.sage_addr = ENDIAN_SWAP32(sensordinit->sage_addr);
		//pCmd->SensordInit_ext.SensordInit.buff_addr = ENDIAN_SWAP32(sensordinit->buff_addr);
		//pCmd->SensordInit_ext.SensordInit.freq_list = ENDIAN_SWAP32(sensordinit->freq_list);
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_SENSORD_INIT));
		wlInterruptUnMask(netdev, MACREG_A2HRIC_NEWDP_SENSORD);
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_SENSORD_INIT);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;

	}

	int wlFwNewDP_sensorD_cmd(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_NEWDP_SENSORD_CMD *pCmd =
			(HostCmd_FW_NEWDP_SENSORD_CMD *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_SENSORD_CMD));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_SENSORD_CMD);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_SENSORD_CMD));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_SENSORD_CMD));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_SENSORD_CMD);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;

	}

#ifndef SOC_W906X
	int wlFwNewDP_DMAThread_start(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_DMATHREAD_START_CMD *pCmd =
			(HostCmd_FW_DMATHREAD_START_CMD *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_DMATHREAD_START_CMD));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_DMATHREAD_START);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_DMATHREAD_START_CMD));
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_DMATHREAD_START_CMD));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_DMATHREAD_START);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
#endif /* #ifndef SOC_W906X */
	void wlFwNewDP_wifiarb_dfs_detect(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		char evBuf[64];

		sprintf(evBuf, "wifiarb_dfs_detect");
		WLSNDEVT(netdev, IWEVCUSTOM,
			 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0],
			 evBuf);
		return;
	}

	int wlFwNewDP_wifiarb_post_req_intr(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		int ret;
		struct siginfo info;
		struct task_struct *t;
		sfw_notification_t sfw_notify;

		/* send the signal */
		memset(&info, 0, sizeof(struct siginfo));
		memset(&sfw_notify, 0, sizeof(sfw_notification_t));
		//printk("wifiarb_post_req_intr send signal\n");
		info.si_signo = SIG_wifiarb_post_req_intr;
		info.si_code = SI_QUEUE;	// this is bit of a trickery: SI_QUEUE is normally used by sigqueue from user space,
		// and kernel space should use SI_KERNEL. But if SI_KERNEL is used the real_time data
		// is not delivered to the user space signal handler function.
		if (wlpptr->cardindex == 0) {
			sfw_notify.devnum = 0;

		} else if (wlpptr->cardindex == 1) {
			sfw_notify.devnum = 1;
		}
		sfw_notify.notification_src =
			wifiarb_post_req_intr_notification;
		info.si_int = *(int *)&sfw_notify;
		rcu_read_lock();
		t = pid_task(find_pid_ns
			     (wlpptr->wlpd_p->PostReqSiginfo.pid, &init_pid_ns),
			     PIDTYPE_PID);
		if (t == NULL) {
			printk("no such pid\n");
			rcu_read_unlock();
			return -ENODEV;
		}
		rcu_read_unlock();
		ret = send_sig_info(SIG_wifiarb_post_req_intr, &info, t);	//send the signal
		if (ret < 0) {
			printk("error sending signal\n");
		}
		return 0;
	}

	int wlFwNewDP_sensord_set_blanking(struct net_device *netdev,
					   u8 * blankingmask) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_NEWDP_SENSORD_SET_BLANKING *pCmd =
			(HostCmd_FW_NEWDP_SENSORD_SET_BLANKING *) & wlpptr->
			pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00,
		       sizeof(HostCmd_FW_NEWDP_SENSORD_SET_BLANKING));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_SENSORD_SET_BLANKING);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_NEWDP_SENSORD_SET_BLANKING));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->blankingmask = *blankingmask;
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_SENSORD_SET_BLANKING));
		printk("blankingmask = %d \n", pCmd->blankingmask);
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_SENSORD_SET_BLANKING);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwNewDP_bfmr_config(struct net_device *netdev,
				  bfmr_config_t * BFMRconfig, UINT8 action) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_NEWDP_BFMR_CONFIG *pCmd =
			(HostCmd_FW_NEWDP_BFMR_CONFIG *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_BFMR_CONFIG));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_BFMR_CONFIG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_BFMR_CONFIG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		memcpy((UINT8 *) & pCmd->BFMRconfig, (UINT8 *) BFMRconfig,
		       sizeof(bfmr_config_t));
		pCmd->BFMRconfig.chan = ENDIAN_SWAP16(BFMRconfig->chan);
		pCmd->Action = action;	//0: Only use ht_cap, vht_cap_data, flags from BFMRconfig , 1: use all setting from BFMRconfig

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_BFMR_CONFIG));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_BFMR_CONFIG);

		printk("chan =%d, bw =%d, rx_ant =%d, tx_ant =%d \n",
		       pCmd->BFMRconfig.chan, pCmd->BFMRconfig.bw,
		       pCmd->BFMRconfig.rx_ant, pCmd->BFMRconfig.tx_ant);
		//printk("HT_cap\n");
		//wlDumpData(pCmd->BFMRconfig.ht_cap, 28);
		//printk("VHT_cap\n");
		//wlDumpData(pCmd->BFMRconfig.vht_cap_data, 12);
		//printk("ADDR\n");
		//wlDumpData(pCmd->BFMRconfig.addr, 6);

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwNewDP_bfmr_sbf_open(struct net_device *netdev,
				    wlcfg_sbf_open_t * WlcfgsbfOpen) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		extStaDb_StaInfo_t *pStaInfo;

		bfmr_sbf_open_t BFMRsbfOpen;

		HostCmd_FW_NEWDP_BFMR_SBF_OPEN *pCmd =
			(HostCmd_FW_NEWDP_BFMR_SBF_OPEN *) & wlpptr->pCmdBuf[0];
		unsigned long flags;
		int retval = FAIL;

		memset(&BFMRsbfOpen, 0, sizeof(bfmr_sbf_open_t));
		if (WlcfgsbfOpen->reassign == 0) {
			if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) WlcfgsbfOpen->
							    CurrentStaMac,
							    STADB_DONT_UPDATE_AGINGTIME))
			    == NULL) {
				printk("get current sta info fail\n");
				return retval;
			}
			memcpy(BFMRsbfOpen.addr, WlcfgsbfOpen->CurrentStaMac,
			       6);
			BFMRsbfOpen.sbf_slot = pStaInfo->sbf_slot;
			printk("non assign slot=%d\n", pStaInfo->sbf_slot);
		} else {
			u8 slotTmp;

			if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) WlcfgsbfOpen->
							    CurrentStaMac,
							    STADB_DONT_UPDATE_AGINGTIME))
			    == NULL) {
				printk("get current sta info fail\n");
				return retval;
			}
			if (pStaInfo->sbf_slot == 0xff) {
				printk("error: should not be 0xff\n");
			}
			slotTmp = pStaInfo->sbf_slot;
			pStaInfo->sbf_slot = 0xFF;
			printk("reassign slot = %d\n", slotTmp);
			if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) WlcfgsbfOpen->
							    ReassignStaMac,
							    STADB_DONT_UPDATE_AGINGTIME))
			    == NULL) {
				printk("get reassign sta info fail\n");
				return retval;
			}
			memcpy(BFMRsbfOpen.addr, WlcfgsbfOpen->ReassignStaMac,
			       6);
			BFMRsbfOpen.sbf_slot = slotTmp;
		}
		memcpy(BFMRsbfOpen.vht_cap_data,
		       ((UINT8 *) & pStaInfo->vhtCap) + 2, 12);
		if (pStaInfo->ClientMode == GONLY_MODE ||
		    pStaInfo->ClientMode == BONLY_MODE ||
		    pStaInfo->ClientMode == AONLY_MODE) {
			//legacy client?
			memset(BFMRsbfOpen.ht_cap, 0, 28);
		} else {
			memcpy(BFMRsbfOpen.ht_cap, (UINT8 *) & pStaInfo->HtElem,
			       28);
		}
		//BFMRsbfOpen.rate_map ????????????? to do
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_BFMR_SBF_OPEN));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_BFMR_SBF_OPEN);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_BFMR_SBF_OPEN));
		memcpy((UINT8 *) & pCmd->BFMRsbfOpen, (UINT8 *) & BFMRsbfOpen,
		       sizeof(bfmr_sbf_open_t));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		//printk("bfmr_sbf_open:HT_cap\n");
		//wlDumpData(pCmd->BFMRsbfOpen.ht_cap, 28);
		//printk("bfmr_sbf_open:VHT_cap, ID = %d\n", *(UINT8 *)&pStaInfo->vhtCap);
		//wlDumpData(pCmd->BFMRsbfOpen.vht_cap_data, 12);
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_BFMR_SBF_OPEN));
		if (wlexecuteCommand(netdev, HostCmd_CMD_NEWDP_BFMR_SBF_OPEN)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		if (WlcfgsbfOpen->reassign == 0 && pStaInfo->sbf_slot == 0xff) {
			//pStaInfo->sbf_slot = pCmd->BFMRsbfOpen.sbf_slot;
			pStaInfo->sbf_slot = 66;	//testing

		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return SUCCESS;
	}

	int wlFwNewDP_bfmr_sbf_close(struct net_device *netdev,
				     wlcfg_sbf_close_t * WlcfgsbfClose) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		extStaDb_StaInfo_t *pStaInfo;
		bfmr_sbf_close_t BFMRsbfClose;
		HostCmd_FW_NEWDP_BFMR_SBF_CLOSE *pCmd =
			(HostCmd_FW_NEWDP_BFMR_SBF_CLOSE *) & wlpptr->
			pCmdBuf[0];
		unsigned long flags;
		int retval = FAIL;

		memset(&BFMRsbfClose, 0, sizeof(bfmr_sbf_close_t));
		if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						    (IEEEtypes_MacAddr_t *)
						    WlcfgsbfClose->StaMac,
						    STADB_DONT_UPDATE_AGINGTIME))
		    == NULL) {
			printk("bfmr_sbf_close:get current sta info fail\n");
			return retval;
		}
		BFMRsbfClose.sbf_slot = pStaInfo->sbf_slot;
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_BFMR_SBF_CLOSE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_BFMR_SBF_CLOSE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_BFMR_SBF_CLOSE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		memcpy((UINT8 *) & pCmd->BFMRsbfClose, (UINT8 *) & BFMRsbfClose,
		       sizeof(bfmr_sbf_close_t));
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_BFMR_SBF_CLOSE));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_BFMR_SBF_CLOSE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return SUCCESS;
	}

	int wlFwSetPowerPerRate(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_SET_POWER_PER_RATE *pCmd =
			(HostCmd_FW_NEWDP_SET_POWER_PER_RATE *) & wlpptr->
			pCmdBuf[0];
		unsigned long flags;
		int retval = FAIL;
#ifdef SOC_W8964
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_SET_POWER_PER_RATE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->pPhyInfoPwrTbl =
			(UINT32) ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].
					       pPhyInfoPwrTbl);
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_SET_POWER_PER_RATE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
#else
		u32 len;
		u32 offset;
		u32 total_size, maxbuflen;
		u8 *p = wlpptr->wlpd_p->descData[0].pInfoPwrTbl;

		total_size = sizeof(Info_rate_power_table_t);
		maxbuflen =
			(4096 - sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		offset = 0;

		while (offset < total_size) {
			MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
			memset(pCmd, 0x00,
			       sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));

			pCmd->CmdHdr.Cmd =
				ENDIAN_SWAP16
				(HostCmd_CMD_NEWDP_SET_POWER_PER_RATE);
			pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
			pCmd->offset = offset;

			if ((offset + maxbuflen) < total_size) {
				len = maxbuflen;
				pCmd->last = 0;
			} else {
				len = total_size - offset;
				pCmd->last = 1;
			}

			memcpy((u8 *) pCmd->payload, &p[offset], len);
			offset += len;
			pCmd->CmdHdr.Length =
				(len +
				 sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));

			//printk("HostCmd_CMD_NEWDP_SET_POWER_PER_RATE: len:%u, last:%u\n", len, pCmd->last);
			//mwl_hex_dump((u8 *)pCmd->payload, len);

			WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
					sizeof
					(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
			retval = wlexecuteCommand(netdev,
						  HostCmd_CMD_NEWDP_SET_POWER_PER_RATE);
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

			if (retval != SUCCESS)
				return retval;
		}
#endif
		return SUCCESS;
	};

#if defined(SOC_W906X) || defined(SOC_W9068)
	int wlFwMuUserPosition(struct net_device *netdev, u16 action, u8 gid,
			       u8 usr_pos) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_MU_USER_POSIOTION *pCmd =
			(HostCmd_MU_USER_POSIOTION *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "wlFwMuUserPosition");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_MU_USER_POSIOTION));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_MU_USER_POSITION);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_MU_USER_POSIOTION));
		pCmd->Action = ENDIAN_SWAP16(action);
		pCmd->gid = gid;
		pCmd->usr_pos = usr_pos;

		retval = wlexecuteCommand(netdev, HostCmd_CMD_MU_USER_POSITION);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (retval != SUCCESS)
			printk("\n\n wlFwMuUserPosition() fail %d \n\n",
			       retval);

		return retval;
	}

	int wlFwGetPowerPerRate(struct net_device *netdev, UINT32 RatePower,
				UINT16 * dBm, UINT8 * ant) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_NEWDP_SET_POWER_PER_RATE *pCmd =
			(HostCmd_FW_NEWDP_SET_POWER_PER_RATE *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		rate_power_W906x_t *rp;
		//Info_rate_power_table_t *pratepower;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_GET_POWER_PER_RATE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_NEWDP_SET_POWER_PER_RATE) +
				      sizeof(u32));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		//dralee
		//pCmd->pPhyInfoPwrTbl   = (UINT32)ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].pPhyInfoPwrTbl);
		*(u32 *) pCmd->payload = (u32) RatePower;

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_GET_POWER_PER_RATE);

		if (!retval) {
			u64 rpvalue = 0;

			memcpy((void *)&rpvalue, (void *)pCmd->payload,
			       sizeof(u64));
			printk("rpvalue:%llx\n", rpvalue);
			rp = (rate_power_W906x_t *) & rpvalue;

			dBm[0] = (UINT16) rp->Power_pri;	//*(u16 *)&pCmd->payload[2];
			dBm[1] = (UINT16) rp->Power_2nd;	//*(u16 *)&pCmd->payload[4];
			*ant = rp->Active_Tx;
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;

	}

	UINT32 wlFwSetProtectMode(struct net_device * netdev,
				  UINT32 action, UINT32 * pMode) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_PROTECTION_MODE *pCmd =
			(HostCmd_PROTECTION_MODE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_PROTECTION_MODE));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_PROTECTION_MODE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_PROTECTION_MODE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->Action = ENDIAN_SWAP16(action);

		if (action == HostCmd_ACT_GEN_SET) {
			pCmd->mode = ENDIAN_SWAP16(*pMode);
		}

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_PROTECTION_MODE));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_PROTECTION_MODE);

		if (action == HostCmd_ACT_GEN_GET) {
			*pMode = ENDIAN_SWAP16(pCmd->mode);
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	UINT32 wlFwSetMib(struct net_device * netdev,
			  UINT32 action, UINT32 mibIdx, UINT32 * pValue,
			  UINT32 * pNum) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_MIB_CFG *pCmd =
			(HostCmd_FW_MIB_CFG *) & wlpptr->pCmdBuf[0];
		int retval = FAIL, i;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_MIB_CFG));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_MIB_CFG);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_MIB_CFG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->action = ENDIAN_SWAP16(action);
		pCmd->mibIdx = ENDIAN_SWAP16(mibIdx);
		pCmd->num = ENDIAN_SWAP16(*pNum);

		for (i = 0; i < *pNum; i++)
			pCmd->value[i] = ENDIAN_SWAP32(pValue[i]);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_MIB_CFG));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_MIB_CFG);

		*pNum = ENDIAN_SWAP16(pCmd->num);
		for (i = 0; i < *pNum; i++)
			pValue[i] = ENDIAN_SWAP32(pCmd->value[i]);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	UINT32 wlFwSetSchedMode(struct net_device * netdev, UINT16 action,
				UINT32 mode_selected, void *pCfg, UINT16 len,
				UINT16 * pStatus) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_SCHED_MODE_CFG *pCmd =
			(HostCmd_SCHED_MODE_CFG *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_MIB_CFG));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SCHED_MODE_CFG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_SCHED_MODE_CFG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->action = ENDIAN_SWAP16(action);
		pCmd->mode_selected = ENDIAN_SWAP32(mode_selected);

		if (pCfg && len)
			memcpy((void *)&pCmd->ul_ofdma, pCfg, len);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_SCHED_MODE_CFG));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SCHED_MODE_CFG);

		if (pCfg && len)
			memcpy(pCfg, (void *)&pCmd->ul_ofdma, len);

		*pStatus = ENDIAN_SWAP16(pCmd->status);

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	UINT32 wlFwSetWfaTest(struct net_device * netdev,
			      UINT32 action, UINT32 version, UINT32 testId,
			      UINT32 stepId, void *cfg, UINT32 cfgLen) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_WFA_TEST_CMD *pCmd =
			(HostCmd_WFA_TEST_CMD *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_WFA_TEST_CMD));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_WFA_TEST);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_WFA_TEST_CMD) + cfgLen);
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->action = ENDIAN_SWAP16(action);
		pCmd->version = ENDIAN_SWAP32(version);
		pCmd->testId = ENDIAN_SWAP32(testId);
		pCmd->stepId = ENDIAN_SWAP32(stepId);

		if (cfg && cfgLen) {
			memcpy((void *)(pCmd + 1), cfg, cfgLen);
		}

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_WFA_TEST_CMD) + cfgLen);
		retval = wlexecuteCommand(netdev, HostCmd_CMD_WFA_TEST);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	UINT32 wlFwSentTriggerFrameCmd(struct net_device * netdev, UINT8 action,
				       UINT8 type, UINT32 rateInfo,
				       UINT32 period, UINT32 padNum,
				       void *pData) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_DS_TRIGGER_FRAME *pCmd =
			(HostCmd_DS_TRIGGER_FRAME *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_DS_TRIGGER_FRAME));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_TRIGGER_FRAME);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_DS_TRIGGER_FRAME));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->action = action;
		pCmd->type = type;
		pCmd->rateInfo = ENDIAN_SWAP32(rateInfo);
		pCmd->period = ENDIAN_SWAP32(period);
		pCmd->padNum = ENDIAN_SWAP16(padNum);

		if ((action > 0) && pData) {
			memcpy((void *)&pCmd->tf, pData, sizeof(tf_basic_t));
		}

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_DS_TRIGGER_FRAME));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_TRIGGER_FRAME);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

#else

	int wlFwGetPowerPerRate(struct net_device *netdev, UINT32 RatePower,
				UINT8 * trpcid, UINT16 * dBm, UINT16 * ant) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		HostCmd_FW_NEWDP_SET_POWER_PER_RATE *pCmd =
			(HostCmd_FW_NEWDP_SET_POWER_PER_RATE *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		Info_rate_power_table_t *pratepower;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_NEWDP_GET_POWER_PER_RATE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->pPhyInfoPwrTbl =
			(UINT32) ENDIAN_SWAP32(wlpptr->wlpd_p->descData[0].
					       pPhyInfoPwrTbl);

		pratepower =
			(Info_rate_power_table_t *) wlpptr->wlpd_p->descData[0].
			pInfoPwrTbl;
		pratepower->RatePwrTbl.RatePower[0] = ENDIAN_SWAP32(RatePower);

		memset(trpcid, 0x00, sizeof(UINT8));
		memset(dBm, 0x00, sizeof(UINT16));

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_SET_POWER_PER_RATE));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_GET_POWER_PER_RATE);

		if (!retval) {
			memcpy(trpcid, &pratepower->RatePwrTbl.RatePower[1],
			       sizeof(UINT8));
			memcpy(dBm, &pratepower->RatePwrTbl.RatePower[2],
			       sizeof(UINT16));
			memcpy(ant, &pratepower->RatePwrTbl.RatePower[3],
			       sizeof(UINT16));
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;

	}
#endif

	int wlFwRadioStatusNotification(struct net_device *netdev,
					UINT32 action) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION *pCmd =
			(HostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION *) &
			wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00,
		       sizeof(HostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16
			(HostCmd_CMD_NEWDP_RADIO_STATUS_NOTIFICATION);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof
				      (HostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Action = ENDIAN_SWAP32(action);	//1: enable, 0: disable
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof
				(HostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_RADIO_STATUS_NOTIFICATION);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

/*Function to send a continuous fixed len pkt generated in fw using rate info supplied by user*/
	int wlFwSetTxContinuous(struct net_device *netdev, UINT8 mode,
				UINT32 rateinfo) {
		int retval = FAIL;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_TXCONTINUOUS *pCmd =
			(HostCmd_FW_TXCONTINUOUS *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_TXCONTINUOUS));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_TX_CONTINUOUS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_TXCONTINUOUS));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		pCmd->mode = mode;
		pCmd->rate_info = ENDIAN_SWAP32(rateinfo);
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_SET_TX_CONTINUOUS);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	int wlFwNewDP_amsducfg(struct net_device *netdev, amsducfg_t * amsducfg) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_AMSDU_CFG *pCmd =
			(HostCmd_FW_NEWDP_AMSDU_CFG *) & wlpptr->pCmdBuf[0];
		unsigned long flags;
		int retval = FAIL;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_AMSDU_CFG));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_AMSDU_CFG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_AMSDU_CFG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		memcpy((UINT8 *) & pCmd->amsducfg, (UINT8 *) amsducfg,
		       sizeof(amsducfg_t));
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_AMSDU_CFG));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_NEWDP_AMSDU_CFG);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

/*Function to set Receiver Start of Packet Detection Threshold (Rx SOP) threshold in fw*/
	int wlFwNewDP_RxSOP(struct net_device *netdev, UINT8 params,
			    UINT8 threshold1, UINT8 threshold2) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_RX_DETECT *pCmd =
			(HostCmd_FW_NEWDP_RX_DETECT *) & wlpptr->pCmdBuf[0];
		unsigned long flags;
		int retval = FAIL;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_RX_DETECT));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_RX_DETECT);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_RX_DETECT));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->rx_detect_params = params;
		pCmd->rx_detect_threshold1 = threshold1;
		pCmd->rx_detect_threshold2 = threshold2;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_RX_DETECT));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_NEWDP_RX_DETECT);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	int wlFwNewDP_set_sku(struct net_device *netdev, UINT32 sku) {
		int retval = FAIL;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_SKU *pCmd =
			(HostCmd_FW_SET_SKU *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_SKU));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_SKU);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_SKU));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->sku = ENDIAN_SWAP32(sku);
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_SKU);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;

	}

	int wlFwNewDP_NDPA_UseTA(struct net_device *netdev, UINT32 enable) {
		int retval = FAIL;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NDPA_USETA *pCmd =
			(HostCmd_FW_NDPA_USETA *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NDPA_USETA));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_NDPA_USETA);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NDPA_USETA));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Enable = ENDIAN_SWAP32(enable);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_NDPA_USETA));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_NEWDP_NDPA_USETA);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;

	}

#endif
#ifdef WTP_SUPPORT
	int wlFwSetWtpMode(struct net_device *dev) {
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		HostCmd_FW_SET_WTP_MODE *pCmd =
			(HostCmd_FW_SET_WTP_MODE *) & wlpptr->pCmdBuf[0];
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_WTP_MODE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_WTP_MODE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_WTP_MODE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = vmacSta_p->VMacEntry.macId;
		pCmd->enabled = mib->mib_wtp_cfg->wtp_enabled;

		vmacSta_p->wtp_info.WTP_enabled = mib->mib_wtp_cfg->wtp_enabled;
		vmacSta_p->wtp_info.mac_mode = mib->mib_wtp_cfg->mac_mode;
		vmacSta_p->wtp_info.tunnel_mode =
			mib->mib_wtp_cfg->frame_tunnel_mode;
		vmacSta_p->wtp_info.RF_ID = vmacSta_p->VMacEntry.phyHwMacIndx;
		vmacSta_p->wtp_info.WLAN_ID = vmacSta_p->VMacEntry.macId;

		printk("WTP_nable=%d  macmode=%d tunnel_mode=%d RFID=%d WLANID=%d\n", vmacSta_p->wtp_info.WTP_enabled, vmacSta_p->wtp_info.mac_mode, vmacSta_p->wtp_info.tunnel_mode, vmacSta_p->wtp_info.RF_ID, vmacSta_p->wtp_info.WLAN_ID);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_SET_WTP_MODE));
		//retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_WTP_MODE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwSetPropProbeIE(struct net_device *netdev, UINT8 * extProbeIE,
			       UINT16 len) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_SET_WSC_IE *pCmd =
			(HostCmd_SET_WSC_IE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		if (extProbeIE == NULL)
			return retval;
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_SET_WSC_IE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_WSC_IE);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_SET_WSC_IE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->ieType = ENDIAN_SWAP16(1);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		memcpy(&pCmd->wscIE.probeRespIE, extProbeIE, len);

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_SET_WSC_IE));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_WSC_IE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwGetMUSet(struct net_device *netdev, UINT8 index) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		int j = 0;
		HostCmd_FW_GET_MU_SET *pCmd =
			(HostCmd_FW_GET_MU_SET *) & wlpptr->pCmdBuf[0];
		UINT8 *ptr;

		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		//memset(pCmd, 0x00, sizeof(FWCmdHdr)+sizeof(const struct macaddr));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_MU_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_MU_SET));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = 1;
		pCmd->index = index;

		ptr = (void *)pCmd;

		if (wlexecuteCommand(netdev, HostCmd_CMD_GET_MU_SET)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		printk("GID:%d OWN=%d\n", pCmd->muset[index].GID,
		       pCmd->muset[index].Own);

		for (j = 0; j < MU_MIMO_MAX_USER; j++) {
			printk("RateCode : %x StnID%x\n",
			       pCmd->muset[index].mustn[j].RateCode,
			       pCmd->muset[index].mustn[j].StnId);
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return 0;
	}

#ifdef MRVL_MUG_ENABLE
	int wlFwGetMUInfo(struct net_device *netdev, int groups_only) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_MU_INFOT *pCmd =
			(HostCmd_FW_GET_MU_INFOT *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_MU_INFOT));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_MU_INFO);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_MU_INFOT));
		pCmd->CmdHdr.macid = 1;

		pCmd->groups_only = groups_only;

		if (wlexecuteCommand(netdev, HostCmd_CMD_GET_MU_INFO)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwSetMUConfig(struct net_device *netdev, u32 corr_thr_decimal,
			    u16 sta_cep_age_thr, u16 period_ms) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_MU_CONFIGT *pCmd =
			(HostCmd_FW_SET_MU_CONFIGT *) & wlpptr->pCmdBuf[0];
		//u8 * p_data = (u8 *)&(pCmd->groups);
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_MU_CONFIGT));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MU_CONFIG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_MU_CONFIGT));
		pCmd->CmdHdr.macid = 1;

		pCmd->corr_thr_decimal = corr_thr_decimal;
		pCmd->sta_cep_age_thr = sta_cep_age_thr;
		pCmd->period_ms = period_ms;

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_MU_CONFIG)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwMUGEnable(struct net_device *netdev, int enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_MUG_ENABLET *pCmd =
			(HostCmd_FW_MUG_ENABLET *) & wlpptr->pCmdBuf[0];
		//u8 * p_data = (u8 *)&(pCmd->groups);
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_MUG_ENABLET));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_MUG_ENABLE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_MUG_ENABLET));
		pCmd->CmdHdr.macid = 1;

		pCmd->enable = enable;

		if (wlexecuteCommand(netdev, HostCmd_CMD_MUG_ENABLE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwSetMUDma(struct net_device *netdev, u_int32_t base,
			 u_int32_t size) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_MU_DMAT *pCmd =
			(HostCmd_FW_SET_MU_DMAT *) & wlpptr->pCmdBuf[0];
		//u8 * p_data = (u8 *)&(pCmd->groups);
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_MU_DMAT));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MU_DMA);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_MU_DMAT));
		pCmd->CmdHdr.macid = 1;

		pCmd->dma_buf_base = base;
		pCmd->dma_buf_size = size;

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_MU_DMA)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}
#endif /* #ifdef MRVL_MUG_ENABLE */

#ifdef SOC_W906X
	int wlFwSetMUSet(struct net_device *netdev, UINT8 Option, UINT8 GID,
			 UINT8 Setindex, UINT16 * Stn)
#else
	int wlFwSetMUSet(struct net_device *netdev, UINT8 Option, UINT8 GID,
			 UINT8 Setindex, UINT16 Stn1, UINT16 Stn2, UINT16 Stn3)
#endif
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_MU_SET *pCmd =
			(HostCmd_FW_SET_MU_SET *) & wlpptr->pCmdBuf[0];
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		MIB_802DOT11 *mib;
		unsigned long flags;
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		if (vmacSta_p->master) {
			vmacSta_p = vmacSta_p->master;
		}
		mib = vmacSta_p->Mib802dot11;
		if ((mib->DL_mimo_enable == 0) && (Option > 0)) {
			/* Option:1 is AC-DLMIMO, 2 is AX-DLMIMO */
			return 1;
		}

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_MU_SET));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MU_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_MU_SET));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = 1;
		pCmd->Option = Option;
		pCmd->GID = GID;
		pCmd->Setindex = Setindex;
#ifdef SOC_W906X
		pCmd->Ofdma = FALSE;	//hardcode for non-ofdma. will change later.
		if (Stn)	//Stn might be null for Del Mu Set
			memcpy(&pCmd->StnID[0], Stn, sizeof(pCmd->StnID));
		else if (!Option) {	// if Del Mu Set and Stn is null, set 0xFFFF in first stn.
			pCmd->StnID[0] = 0xFFFF;
		}
#else
		pCmd->StnID[0] = Stn1;
		pCmd->StnID[1] = Stn2;
		pCmd->StnID[2] = Stn3;
#endif

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_MU_SET)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if ((result == HostCmd_RESULT_OK) ||
		    //Option==0: Del_MUSet. Firmware will still clear GID if HostCmd_RESULT_PENDING is returned
		    ((result == HostCmd_RESULT_PENDING) && (Option == 0)))
			return 1;
		else
			return 0;
	}

#ifdef SOC_W906X
	int wlFwSetMBSSIDSet(struct net_device *netdev, UINT8 Option,
			     UINT8 groupid, UINT8 primary, UINT32 members) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_MBSSID_SET *pCmd =
			(HostCmd_FW_SET_MBSSID_SET *) & wlpptr->pCmdBuf[0];
		unsigned long flags;
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MBSSID_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_MBSSID_SET));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = 1;
		pCmd->Option = Option;
		pCmd->sid = groupid;	//mbssid set id. max value: MAX_MBSSID_SET
		pCmd->Primary = primary;
		pCmd->bitmap = members;	//mbssid set members bitmap       
		pCmd->max_bss_indicator = Get_MaxBssid_Indicator(bss_num);

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_MBSSID_SET)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return 1;
		else
			return 0;
	}
#endif

#if defined(SOC_W906X) || defined(SOC_W9068)
	int wlFwOBW16_11b(struct net_device *netdev, u8 Enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_OBW16_11B *pCmd =
			(HostCmd_FW_OBW16_11B *) & wlpptr->pCmdBuf[0];
		unsigned long flags;
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_OBW16_11B);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_OBW16_11B));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = 1;
		pCmd->Enable = Enable;

		if (wlexecuteCommand(netdev, HostCmd_CMD_OBW16_11B)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return SUCCESS;
		else
			return FAIL;
	}
#endif

#ifdef AIRTIME_FAIRNESS

	int wlFwAtfEnable(struct net_device *netdev, u8 enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_ATF_ENABLE *pCmd =
			(HostCmd_FW_ATF_ENABLE *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_ATF_ENABLE));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_ATF_ENABLE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_ATF_ENABLE));
		pCmd->CmdHdr.macid = 1;
		pCmd->enable = enable;

		if (wlexecuteCommand(netdev, HostCmd_CMD_ATF_ENABLE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwSetAtfCfg(struct net_device *netdev, UINT8 param, UINT16 value) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_ATF_CFG *pCmd =
			(HostCmd_FW_SET_ATF_CFG *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_ATF_CFG));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_ATF_CFG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_ATF_CFG));
		pCmd->CmdHdr.macid = 1;

		pCmd->param = param;
		pCmd->value = value;

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_ATF_CFG)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwGetAtfCfg(struct net_device *netdev, UINT16 * atf_param) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_ATF_CFG *pCmd =
			(HostCmd_FW_GET_ATF_CFG *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		int ret = 0;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_ATF_CFG));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_ATF_CFG);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_ATF_CFG));
		pCmd->CmdHdr.macid = 1;

		if (wlexecuteCommand(netdev, HostCmd_CMD_GET_ATF_CFG)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			ret = FAIL;
			goto exit;
		}

		if (pCmd->CmdHdr.Result != HostCmd_RESULT_OK) {
			ret = FAIL;
			goto exit;
		}

		atf_param[0] = pCmd->vi_weight;
		atf_param[1] = pCmd->be_weight;
		atf_param[2] = pCmd->bk_weight;
		atf_param[3] = pCmd->reserved_airtime;

exit:
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return ret;
	}

	int wlFwAtfDebugEnable(struct net_device *netdev, u8 debug_feature,
			       u8 enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_ATF_DEBUG_ENABLE *pCmd =
			(HostCmd_FW_ATF_DEBUG_ENABLE *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_ATF_DEBUG_ENABLE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_ATF_DEBUG_ENABLE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_ATF_DEBUG_ENABLE));
		pCmd->CmdHdr.macid = 1;

		pCmd->enable = enable;
		pCmd->feature = debug_feature;

		if (wlexecuteCommand(netdev, HostCmd_CMD_ATF_DEBUG_ENABLE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}
		result = pCmd->CmdHdr.Result;

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwSetAtfDma(struct net_device *netdev, u_int32_t base,
			  u_int32_t size) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_ATF_DMA *pCmd =
			(HostCmd_FW_SET_ATF_DMA *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_ATF_DMA));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_ATF_DMA);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_ATF_DMA));
		pCmd->CmdHdr.macid = 1;

		pCmd->dma_buf_base = base;
		pCmd->dma_buf_size = size;

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_ATF_DMA)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

	int wlFwAtfTransfertDone(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_ATF_TRANSFERT_DONE *pCmd =
			(HostCmd_FW_ATF_TRANSFERT_DONE *) & wlpptr->pCmdBuf[0];
		unsigned long flags;	/* NOTE: Used for MWL_SPIN_LOCK */
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset(pCmd, 0x00, sizeof(HostCmd_FW_ATF_TRANSFERT_DONE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_ATF_TRANSFERT_DONE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_ATF_TRANSFERT_DONE));
		pCmd->CmdHdr.macid = 1;

		if (wlexecuteCommand(netdev, HostCmd_CMD_ATF_TRANSFERT_DONE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		if (result != HostCmd_RESULT_OK)
			return FAIL;

		return 0;
	}

#endif /* AIRTIME_FAIRNESS */

	int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type,
			  UINT16 len, UINT8 * tlvData, char *string_buff) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		unsigned long flags;
		int retval = FAIL;
		int i;

		HostCmd_FW_TLV_CONFIG *pCmd =
			(HostCmd_FW_TLV_CONFIG *) & wlpptr->pCmdBuf[0];

#ifdef WLS_FTM_SUPPORT
		if (type < FTM_MAX_CONFIG) {
			extern void wlsFTM_configureDevice(struct net_device
							   *netdev, UINT8 act,
							   UINT16 type,
							   UINT16 len,
							   UINT8 * tlvData,
							   char *string_buff);
			wlsFTM_configureDevice(netdev, act, type, len, tlvData,
					       string_buff);
			return SUCCESS;
		}
#endif
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_TLV_CONFIG));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_TLV_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_TLV_CONFIG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		if (act) {
			pCmd->CmdHdr.Cmd =
				ENDIAN_SWAP16(HostCmd_CMD_SET_TLV_SET);
			pCmd->TlvType = ENDIAN_SWAP16(type);
			pCmd->TlvLen = ENDIAN_SWAP16(len);
			memcpy(&pCmd->TlvData, tlvData, len);
#ifdef PRD_CSI_DMA
			if (type == 12) {
				wl_util_lock(netdev);
				wlpptr->smacCfgAddr->prd_csi_dma_ddr_addr =
					(UINT32) wlpptr->wlpd_p->pPhysSsuBuf;
				wl_util_unlock(netdev);
			}
#endif
			retval = wlexecuteCommand(netdev,
						  HostCmd_CMD_SET_TLV_SET);
		} else {
			pCmd->TlvType = ENDIAN_SWAP16(type);

			if (type == 20)
				memcpy(&pCmd->TlvData, tlvData, len);
			retval = wlexecuteCommand(netdev,
						  HostCmd_CMD_GET_TLV_SET);
		}
		if (retval) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		if (!act) {
			// Type 1 - AP  WLS
			// Type 2 - STA WLS
			// Type 3 - QUERY WLS Distance and AoA Angle
			// Type 12- AoA Angle Report (no longer supported on W906x - moved into wl_WiFi_AoA_Decode)
			if (type == 3) {
				UINT16 WLS_Distance_INT = 0;
				UINT8 WLS_Distance_DEC = 0;
				SINT16 AoA_Angle_INT = 0;
				UINT8 AoA_Angle_DEC = 0;
				struct file *filp_wls = NULL;

				WLS_Distance_INT =
					(pCmd->TlvData[0] << 8) | (pCmd->
								   TlvData[1]);
				WLS_Distance_DEC = pCmd->TlvData[2];
				AoA_Angle_INT =
					(SINT16) ((pCmd->
						   TlvData[3] << 8) | (pCmd->
								       TlvData
								       [4]));
				AoA_Angle_DEC = pCmd->TlvData[5];
				// Pass back string to buffer for printing out at user space
				// Print back MAC address of distance / angle data
				sprintf(string_buff,
					"\n%d.%02d m\n%d.%02d degrees\nMAC: %02x.%02x.%02x.%02x.%02x.%02x",
					WLS_Distance_INT, WLS_Distance_DEC,
					AoA_Angle_INT, AoA_Angle_DEC,
					pCmd->TlvData[6], pCmd->TlvData[7],
					pCmd->TlvData[8], pCmd->TlvData[9],
					pCmd->TlvData[10], pCmd->TlvData[11]);

				filp_wls =
					filp_open("/tmp/Distance_Output",
						  O_RDWR | O_CREAT | O_TRUNC,
						  0);
				if (!IS_ERR(filp_wls)) {
					__kernel_write(filp_wls, string_buff,
						       strlen(string_buff),
						       &filp_wls->f_pos);
					filp_close(filp_wls, current->files);
					printk("Distance data written to /tmp/Distance_Output\n");
				} else {
					printk("Error opening /tmp/Distance_Output!\n");
				}
			} else if (type == 12) {
#ifdef SOC_W906X
				memcpy(tlvData, &pCmd->TlvData, pCmd->TlvLen);
				goto out;
#else
				// User# Enable MACx6 Packet_Type Packet_Subtype AoA_Angle Detection_Count Timestamp RSSIx4 LOS_Factorx4
				UINT16 WLS_Distance_INT = 10;
				UINT8 WLS_Distance_DEC = 0;
				SINT16 AoA_Angle_INT = 0;
				UINT8 AoA_Angle_DEC = 0;
				UINT32 Timestamp = 0;
				UINT16 LOS_Factor1 = 0;
				UINT16 LOS_Factor2 = 0;
				struct file *filp_wls = NULL;

				// WLS_Distance_INT = (pCmd->TlvData[0] << 8) | (pCmd->TlvData[1]);
				// WLS_Distance_DEC = pCmd->TlvData[2];
				AoA_Angle_INT =
					(SINT16) ((pCmd->
						   TlvData[10] << 8) | (pCmd->
									TlvData
									[11]));
				AoA_Angle_DEC = pCmd->TlvData[12];
				Timestamp =
					(pCmd->TlvData[17] << 24) | (pCmd->
								     TlvData[16]
								     << 16) |
					(pCmd->TlvData[15] << 8) | (pCmd->
								    TlvData
								    [14]);
				LOS_Factor1 =
					(pCmd->TlvData[23] << 8) | (pCmd->
								    TlvData
								    [22]);
				LOS_Factor2 =
					(pCmd->TlvData[25] << 8) | (pCmd->
								    TlvData
								    [24]);
				// Pass back string to buffer for printing out at user space
				// Print back MAC address of distance / angle data
				sprintf(string_buff,
					"\n%d.%02d m\n%d.%01d degrees\n%d count\nTimestamp: %d\nRSSI_A: -%d dBm\nRSSI_B: -%d dBm\nRSSI_C: -%d dBm\nRSSI_D: -%d dBm\nLOS_Factor1: 0.%04d\nLOS_Factor2: 0.%04d\nMAC: %02x.%02x.%02x.%02x.%02x.%02x\nPacket_Type: %02x\nPacket_Subtype: %02x\n",
					WLS_Distance_INT, WLS_Distance_DEC,
					AoA_Angle_INT, AoA_Angle_DEC,
					pCmd->TlvData[13], Timestamp,
					pCmd->TlvData[18], pCmd->TlvData[19],
					pCmd->TlvData[20], pCmd->TlvData[21],
					LOS_Factor1, LOS_Factor2,
					pCmd->TlvData[2], pCmd->TlvData[3],
					pCmd->TlvData[4], pCmd->TlvData[5],
					pCmd->TlvData[6], pCmd->TlvData[7],
					pCmd->TlvData[8], pCmd->TlvData[9]);

				filp_wls =
					filp_open("/tmp/Distance_Output",
						  O_RDWR | O_CREAT | O_TRUNC,
						  0);
				if (!IS_ERR(filp_wls)) {
					__kernel_write(filp_wls, string_buff,
						       strlen(string_buff),
						       &filp_wls->f_pos);
					filp_close(filp_wls, current->files);
					printk("AoA data written to /tmp/Distance_Output\n");
				} else {
					printk("Error opening /tmp/Distance_Output!\n");
				}

				printk("AoA Parameters - 26 Bytes\n");
				printk("AoA Parameters - User#, Enable, MAC_Address[6], Packet_Type, Packet_Subtype, AoA_Angle[3], Detection_Count\n");
				printk("AoA Parameters -        Timestamp, RSSI_A, RSSI_B, RSSI_C, RSSI_D, LOS_Factor1, LOS_Factor2\n");
				printk("AoA Parameters - Error if first byte is 0xFF\n");
#endif
			} else if (type == 20) {
				goto out;
			}
			//else
			{
				printk("GET tlv type=0x%x\n", pCmd->TlvType);
				for (i = 0; i < MAX_TLV_LEN; i++) {
					if ((i != 0) && !(i % 16)) {
						printk("\n");
						printk("%02x ",
						       pCmd->TlvData[i]);
					} else
						printk("%02x ",
						       pCmd->TlvData[i]);
				}
			}
			printk("\n");
		}
out:
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwNewDP_eeprom(struct net_device *netdev, UINT32 offset,
			     UINT8 * data, UINT32 len, UINT16 action) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		unsigned long flags;
		int retval = FAIL;

		HostCmd_FW_EEPROM_CONFIG *pCmd =
			(HostCmd_FW_EEPROM_CONFIG *) & wlpptr->pCmdBuf[0];

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_EEPROM_CONFIG));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_EEPROM_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_EEPROM_CONFIG));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->len = ENDIAN_SWAP32(len);
		pCmd->offset = ENDIAN_SWAP32(offset);
		pCmd->action = ENDIAN_SWAP16(action);
		if (action == HostCmd_ACT_GEN_WRITE) {
			printk("EEPROM: write len=%d data=%02x %02x %02x %02x ...\n", (int)len, data[0], data[1], data[2], data[3]);
			memcpy(&pCmd->data[0], data, len);
		}

		retval = wlexecuteCommand(netdev, HostCmd_CMD_EEPROM_SET);

		if (pCmd->status == SUCCESS) {
			if (action == HostCmd_ACT_GEN_READ) {
				printk("EEPROM: read len=%d data=%02x %02x %02x %02x ...\n", (int)len, pCmd->data[0], pCmd->data[1], pCmd->data[2], pCmd->data[3]);
				memcpy(data, &pCmd->data[0], len);
			}
		} else {
			retval = pCmd->status;
			printk("EEPROM access failed. Error code: %d\n",
			       retval);
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwNewDP_EEPROM_access(struct net_device *netdev, UINT32 action) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_EEPROM_ACCESS *pCmd =
			(HostCmd_FW_EEPROM_ACCESS *) & wlpptr->pCmdBuf[0];

		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_EEPROM_ACCESS));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_EEPROM_ACCESS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_EEPROM_ACCESS));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Action = ENDIAN_SWAP32(action);	//1: lock, 0: unlock
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_EEPROM_ACCESS));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_EEPROM_ACCESS);

		if (pCmd->status == SUCCESS) {
			if (action)
				printk("EEPROM lock success\n");
			else
				printk("EEPROM unlock success\n");
		} else {
			retval = pCmd->status;
			if (action)
				printk("EEPROM lock failed\n");
			else
				printk("EEPROM unlock failed\n");
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

/*Function to set antenna bitmap and trpc id derived from power for off channel*/
	int wlFwNewDP_Set_Offchanpwr(struct net_device *netdev, SINT8 pwr,
				     UINT8 bitmap, UINT8 channel) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_NEWDP_OFFCHANNEL_PWR *pCmd =
			(HostCmd_FW_NEWDP_OFFCHANNEL_PWR *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_PWR));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_NEWDP_OFFCHAN_PWR);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_PWR));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->Pwr = pwr;
		pCmd->AntBitMap = bitmap;
		pCmd->Channel = channel;
		printk("pwr %d, bitmap %d, channel %d \n", pCmd->Pwr,
		       pCmd->AntBitMap, pCmd->Channel);
		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_NEWDP_OFFCHANNEL_PWR));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_NEWDP_OFFCHAN_PWR);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

#endif

	int wlFwGetSysLoad(struct net_device *netdev,
			   radio_cpu_load_t * sys_load) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_SYSLOAD *pCmd =
			(HostCmd_FW_GET_SYSLOAD *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_SYS_LOAD);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_SYSLOAD));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = 1;

		if (wlexecuteCommand(netdev, HostCmd_CMD_GET_SYS_LOAD)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			printk("get fail\n");
			return FAIL;
		}

		if (pCmd->CmdHdr.Result == HostCmd_RESULT_OK) {
			memcpy((UINT8 *) sys_load, (UINT8 *) & pCmd->sysLoad,
			       sizeof(radio_cpu_load_t));
			retval = SUCCESS;
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}
#ifdef FIPS_SUPPORT
	UINT8 *appendDataEntry(UINT8 * ptr, DataEntry_t * pEntry) {
		UINT16 tmpLen;

		tmpLen = ENDIAN_SWAP16(pEntry->Length);
		memcpy(ptr, (void *)&tmpLen, sizeof(tmpLen));
		ptr += sizeof(tmpLen);
		memcpy(ptr, pEntry->Data, pEntry->Length);
		ptr += pEntry->Length;

		return ptr;
	}

	int wlFwSendFipsTest(struct net_device *netdev, UINT32 encdec,
			     UINT32 alg, DataEntry_t * pKey,
			     DataEntry_t * pNounce, DataEntry_t * pAAD,
			     DataEntry_t * pInData, DataEntry_t * pOutput) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		int len, retval = FAIL;
		UINT16 tmpLen;
		UINT8 *ptr;
		HostCmd_FIPS_TEST *pCmd =
			(HostCmd_FIPS_TEST *) & wlpptr->pCmdBuf[0];
		unsigned long flags;
		UINT8 *pOutLocation;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_FIPS_TEST);
		pCmd->CmdHdr.macid = 1;
		pCmd->Status = 0;
		pCmd->EncDec = ENDIAN_SWAP16(encdec);
		pCmd->Algorithm = ENDIAN_SWAP16(alg);
		len = sizeof(HostCmd_FIPS_TEST);
		ptr = (UINT8 *) (pCmd + 1);

		ptr = appendDataEntry(ptr, pKey);
		ptr = appendDataEntry(ptr, pNounce);
		ptr = appendDataEntry(ptr, pAAD);
		pOutLocation = (UINT8 *) ptr;
		ptr = appendDataEntry(ptr, pInData);

		pCmd->CmdHdr.Length = ENDIAN_SWAP16(ptr - (UINT8 *) pCmd);
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		WLDBG_INFO(DBG_LEVEL_0,
			   "wlFwSendFipsTest Command Request :::\n");
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				ENDIAN_SWAP16(pCmd->CmdHdr.Length));

		if (wlexecuteCommand(netdev, HostCmd_CMD_FIPS_TEST)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		WLDBG_INFO(DBG_LEVEL_0,
			   "wlFwSendFipsTest Command Response :::\n");
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				ENDIAN_SWAP16(pCmd->CmdHdr.Length));

		if (pCmd->CmdHdr.Result == HostCmd_RESULT_OK) {
			memcpy((void *)&tmpLen, pOutLocation, sizeof(tmpLen));
			pOutput->Length = ENDIAN_SWAP16(tmpLen);
			if (pOutput->Length > sizeof(pOutput->Data)) {
				pOutput->Length = sizeof(pOutput->Data);
				printk("wlFwSendFipsTest::: output data length out of range\n");
			}
			memcpy(pOutput->Data, (pOutLocation + sizeof(tmpLen)),
			       pOutput->Length);
			retval = SUCCESS;
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return pCmd->Status;
	}

#define TEST_REC   8
	UINT8 encdec[TEST_REC] = { 1, 1, 1, 1, 0, 0, 0, 0 };
	UINT8 algorithm[TEST_REC] =
		{ EncrTypeAes, EncrTypeCcmp256, EncrTypeGcmp128,
    EncrTypeGcmp256,
		EncrTypeAes, EncrTypeCcmp256, EncrTypeGcmp128, EncrTypeGcmp256
	};
	UINT8 algStrDef[TEST_REC][14] =
		{ "aes-ccmp", "aes-ccmp-256", "aes-gcmp", "aes-gcmp-256",
		"aes-ccmp", "aes-ccmp-256", "aes-gcmp", "aes-gcmp-256"
	};
	DataEntry_t Key[TEST_REC] =
		{ {16, {0xC6, 0x7E, 0x81, 0x6B, 0x4B, 0xFB, 0xE2, 0xFB,
			0x54, 0xF6, 0xBD, 0xDF, 0x7C, 0x1C, 0xE1, 0x87}
		   }
	,
	{32, {0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
	      0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f,
	      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	 }
	,
	{16, {0x2e, 0xcd, 0x70, 0xd3, 0x44, 0xac, 0xa4, 0x02,
	      0xfe, 0xf9, 0x90, 0xd5, 0x2a, 0xd4, 0x3e, 0x52}
	 }
	,
	{32, {0xe9, 0x95, 0xf0, 0x70, 0xc9, 0x26, 0x2f, 0xe9,
	      0xa9, 0xb9, 0xd9, 0x11, 0xf4, 0xe5, 0x1e, 0xd6,
	      0x62, 0x4c, 0xb3, 0x67, 0xb1, 0x8c, 0x0c, 0xc4,
	      0x77, 0x98, 0x39, 0xcd, 0x19, 0x02, 0x31, 0xd7}
	 }
	,

	{16, {0xC6, 0x7E, 0x81, 0x6B, 0x4B, 0xFB, 0xE2, 0xFB,
	      0x54, 0xF6, 0xBD, 0xDF, 0x7C, 0x1C, 0xE1, 0x87}
	 }
	,
	{32, {0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
	      0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f,
	      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	 }
	,
	{16, {0x2e, 0xcd, 0x70, 0xd3, 0x44, 0xac, 0xa4, 0x02,
	      0xfe, 0xf9, 0x90, 0xd5, 0x2a, 0xd4, 0x3e, 0x52}
	 }
	,
	{32, {0xe9, 0x95, 0xf0, 0x70, 0xc9, 0x26, 0x2f, 0xe9,
	      0xa9, 0xb9, 0xd9, 0x11, 0xf4, 0xe5, 0x1e, 0xd6,
	      0x62, 0x4c, 0xb3, 0x67, 0xb1, 0x8c, 0x0c, 0xc4,
	      0x77, 0x98, 0x39, 0xcd, 0x19, 0x02, 0x31, 0xd7}
	 }
	};

	DataEntry_t Nounce[TEST_REC] =
		{ {13, {0x01, 0xBF, 0x31, 0xDE, 0x56, 0x72, 0x0F, 0x47,
			0x67, 0x66, 0x87, 0x59, 0xAA}
		   }
	,
	{13, {0x00, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xb5,
	      0x03, 0x97, 0x76, 0xe7, 0x0c}
	 }
	,
	{12, {0xc1, 0xcc, 0x07, 0x4b, 0x72, 0xc0, 0x3d, 0x11,
	      0xe8, 0xa5, 0xa9, 0x8c}
	 }
	,
	{12, {0xe9, 0x7e, 0x06, 0x80, 0x1f, 0xb7, 0xe5, 0x03,
	      0xf7, 0x48, 0xa5, 0x0b}
	 }
	,

	{13, {0x01, 0xBF, 0x31, 0xDE, 0x56, 0x72, 0x0F, 0x47,
	      0x67, 0x66, 0x87, 0x59, 0xAA}
	 }
	,
	{13, {0x00, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xb5,
	      0x03, 0x97, 0x76, 0xe7, 0x0c}
	 }
	,
	{12, {0xc1, 0xcc, 0x07, 0x4b, 0x72, 0xc0, 0x3d, 0x11,
	      0xe8, 0xa5, 0xa9, 0x8c}
	 }
	,
	{12, {0xe9, 0x7e, 0x06, 0x80, 0x1f, 0xb7, 0xe5, 0x03,
	      0xf7, 0x48, 0xa5, 0x0b}
	 }
	};

	DataEntry_t AAD[TEST_REC] =
		{ {22, {0xEA, 0x56, 0x13, 0x7B, 0xD2, 0x85, 0xA1, 0xD8,
			0x3C, 0x54, 0x55, 0x2F, 0x37, 0xAE, 0x65, 0x5B,
			0xDA, 0x02, 0x79, 0x98, 0xCC, 0xE3}
		   }
	,
	{22, {0x08, 0x40, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c,
	      0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xab, 0xae,
	      0xa5, 0xb8, 0xfc, 0xba, 0x00, 0x00}
	 }
	,
	{22, {0x15, 0xf9, 0x51, 0x75, 0x99, 0xe4, 0x06, 0xf0,
	      0x4b, 0xea, 0xae, 0x73, 0xc1, 0x05, 0x46, 0x15,
	      0x72, 0x08, 0x18, 0xc4, 0x99, 0x9e}
	 }
	,
	{22, {0x04, 0x64, 0x33, 0xf8, 0x47, 0xdf, 0x67, 0xb3,
	      0xb7, 0x85, 0xa6, 0x35, 0x21, 0xf1, 0x4f, 0xee,
	      0x59, 0x4e, 0xeb, 0xc3, 0x3b, 0x0e}
	 }
	,

	{22, {0xEA, 0x56, 0x13, 0x7B, 0xD2, 0x85, 0xA1, 0xD8,
	      0x3C, 0x54, 0x55, 0x2F, 0x37, 0xAE, 0x65, 0x5B,
	      0xDA, 0x02, 0x79, 0x98, 0xCC, 0xE3}
	 }
	,
	{22, {0x08, 0x40, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c,
	      0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xab, 0xae,
	      0xa5, 0xb8, 0xfc, 0xba, 0x00, 0x00}
	 }
	,
	{22, {0x15, 0xf9, 0x51, 0x75, 0x99, 0xe4, 0x06, 0xf0,
	      0x4b, 0xea, 0xae, 0x73, 0xc1, 0x05, 0x46, 0x15,
	      0x72, 0x08, 0x18, 0xc4, 0x99, 0x9e}
	 }
	,
	{22, {0x04, 0x64, 0x33, 0xf8, 0x47, 0xdf, 0x67, 0xb3,
	      0xb7, 0x85, 0xa6, 0x35, 0x21, 0xf1, 0x4f, 0xee,
	      0x59, 0x4e, 0xeb, 0xc3, 0x3b, 0x0e}
	 }
	};

	DataEntry_t InData[TEST_REC] = { {2, {0xEE, 0x43}
					  }
	,
	{20, {0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
	      0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
	      0x7e, 0x78, 0xa0, 0x50}
	 }
	,
	{16, {0x1a, 0x4d, 0xa6, 0x30, 0x1e, 0xab, 0x28, 0xc1,
	      0x9c, 0xdf, 0x22, 0xb1, 0x56, 0xab, 0xb9, 0x90}
	 }
	,
	{16, {0xbe, 0x6f, 0x3d, 0xac, 0xf9, 0xcf, 0x62, 0xe1,
	      0x7b, 0x82, 0xbc, 0xa3, 0x71, 0xb0, 0xa8, 0x19}
	 }
	,

	{10, {0xF2, 0x40, 0xC9, 0x34, 0x89, 0x8B, 0xB4, 0xEB,
	      0x7C, 0x27}
	 }
	,
	{36, {0x6d, 0x15, 0x5d, 0x88, 0x32, 0x66, 0x82, 0x56,
	      0xd6, 0xa9, 0x2b, 0x78, 0xe1, 0x1d, 0x8e, 0x54,
	      0x49, 0x5d, 0xd1, 0x74, 0x80, 0xaa, 0x56, 0xc9,
	      0x49, 0x2e, 0x88, 0x2b, 0x97, 0x64, 0x2f, 0x80,
	      0xd5, 0x0f, 0xe9, 0x7b}
	 }
	,
	{32, {0xeb, 0x13, 0x3b, 0xce, 0x32, 0xc2, 0x8b, 0xf8,
	      0xce, 0x4c, 0x22, 0xe3, 0x9e, 0xff, 0x69, 0x1b,
	      0xd2, 0xf1, 0x3c, 0xab, 0x0f, 0xb9, 0xa6, 0x8f,
	      0xd8, 0xc7, 0x36, 0xa8, 0x7e, 0x82, 0x32, 0x35}
	 }
	,
	{32, {0xbe, 0xa5, 0x16, 0x49, 0xe3, 0xa9, 0x0b, 0xfc,
	      0x74, 0x3c, 0x4f, 0x40, 0x8d, 0x53, 0x0b, 0xb3,
	      0x9e, 0x94, 0xc6, 0xd3, 0x37, 0x30, 0x17, 0x8f,
	      0x1b, 0x56, 0xaf, 0xdb, 0xe3, 0x15, 0x36, 0x57}
	 }
	};

	DataEntry_t expData[TEST_REC] =
		{ {10, {0xF2, 0x40, 0xC9, 0x34, 0x89, 0x8B, 0xB4, 0xEB,
			0x7C, 0x27}
		   }
	,
	{36, {0x6d, 0x15, 0x5d, 0x88, 0x32, 0x66, 0x82, 0x56,
	      0xd6, 0xa9, 0x2b, 0x78, 0xe1, 0x1d, 0x8e, 0x54,
	      0x49, 0x5d, 0xd1, 0x74, 0x80, 0xaa, 0x56, 0xc9,
	      0x49, 0x2e, 0x88, 0x2b, 0x97, 0x64, 0x2f, 0x80,
	      0xd5, 0x0f, 0xe9, 0x7b}
	 }
	,
	{32, {0xeb, 0x13, 0x3b, 0xce, 0x32, 0xc2, 0x8b, 0xf8,
	      0xce, 0x4c, 0x22, 0xe3, 0x9e, 0xff, 0x69, 0x1b,
	      0xd2, 0xf1, 0x3c, 0xab, 0x0f, 0xb9, 0xa6, 0x8f,
	      0xd8, 0xc7, 0x36, 0xa8, 0x7e, 0x82, 0x32, 0x35}
	 }
	,
	{32, {0xbe, 0xa5, 0x16, 0x49, 0xe3, 0xa9, 0x0b, 0xfc,
	      0x74, 0x3c, 0x4f, 0x40, 0x8d, 0x53, 0x0b, 0xb3,
	      0x9e, 0x94, 0xc6, 0xd3, 0x37, 0x30, 0x17, 0x8f,
	      0x1b, 0x56, 0xaf, 0xdb, 0xe3, 0x15, 0x36, 0x57}
	 }
	,

	{2, {0xEE, 0x43}
	 }
	,
	{20, {0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
	      0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
	      0x7e, 0x78, 0xa0, 0x50}
	 }
	,
	{16, {0x1a, 0x4d, 0xa6, 0x30, 0x1e, 0xab, 0x28, 0xc1,
	      0x9c, 0xdf, 0x22, 0xb1, 0x56, 0xab, 0xb9, 0x90}
	 }
	,
	{16, {0xbe, 0x6f, 0x3d, 0xac, 0xf9, 0xcf, 0x62, 0xe1,
	      0x7b, 0x82, 0xbc, 0xa3, 0x71, 0xb0, 0xa8, 0x19}
	 }
	};

	DataEntry_t OutData;

	static char *algStr(int algNum) {
		if (algNum < TEST_REC)
			return algStrDef[algNum];
		else
			return NULL;
	}

	int wlFwSendFipsTestAll(struct net_device *netdev) {

		extern void HexStringToHexDigi(char *outHexData,
					       char *inHexString, UINT16 Len);
		int status = 0;
		int i;

		for (i = 0; i < TEST_REC; i++) {
			status = wlFwSendFipsTest(netdev, encdec[i],
						  algorithm[i], &Key[i],
						  &Nounce[i], &AAD[i],
						  &InData[i], &OutData);

			if (memcmp
			    (OutData.Data, expData[i].Data,
			     expData[i].Length)) {
				status |= 1 << i;
				printk("FIPS Failed on %s algorithm %s\n",
				       encdec[i] == 0 ? "dec" : "enc",
				       algStr(i));
			} else
				printk("FIPS Sucess on %s algorithm %s\n",
				       encdec[i] == 0 ? "dec" : "enc",
				       algStr(i));
		}
		return status;
	}
#endif

#ifndef SOC_W906X
	int wlFwSetResetRateMode(struct net_device *netdev,
				 u_int8_t ResetRateMode) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_RESET_RATE_MODE *pCmd =
			(HostCmd_FW_SET_RESET_RATE_MODE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0,
				 "Reset Rate Mode = %d", ResetRateMode);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_RESET_RATE_MODE));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_SET_RESET_RATE_MODE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_RESET_RATE_MODE));
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->ResetRateMode = ResetRateMode;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_FW_SET_RESET_RATE_MODE));

		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_SET_RESET_RATE_MODE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwSetRateUpdateTicks(struct net_device *netdev, UINT32 * n_ticks,
				   UINT8 is_set) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_FW_GEN_U32_ACCESS *pCmd =
			(HostCmd_FW_FW_GEN_U32_ACCESS *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HOSTCMD_CMD_SET_RATE_UPDATE_TICKS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_FW_GEN_U32_ACCESS));
		pCmd->CmdHdr.macid = 1;
		pCmd->val = *n_ticks;
		pCmd->set = is_set;

		if (wlexecuteCommand(netdev, HOSTCMD_CMD_SET_RATE_UPDATE_TICKS)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		if (!is_set)
			*n_ticks = pCmd->val;

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		WLDBG_EXIT(DBG_LEVEL_0);

		return SUCCESS;
	}

	int wlFwSetMutexGet(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		FWCmdHdr *pCmd = (FWCmdHdr *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "wlFwSetMutexGet");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(FWCmdHdr));
		pCmd->Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MTX_GET);
		pCmd->Length = ENDIAN_SWAP16(sizeof(FWCmdHdr));
		pCmd->macid = wlpptr->vmacSta_p->VMacEntry.macId;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(FWCmdHdr));

		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_MTX_GET);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (retval != SUCCESS) {
			printk("\n\n wlFwSetMutexGet() fail %d \n\n", retval);
		}
		return retval;
	}

	int wlFwSetMutexPut(struct net_device *netdev) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		FWCmdHdr *pCmd = (FWCmdHdr *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "wlFwSetMutexPut");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(FWCmdHdr));
		pCmd->Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_MTX_PUT);
		pCmd->Length = ENDIAN_SWAP16(sizeof(FWCmdHdr));
		pCmd->macid = wlpptr->vmacSta_p->VMacEntry.macId;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd, sizeof(FWCmdHdr));

		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_MTX_PUT);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (retval != SUCCESS) {
			printk("\n\n wlFwSetMutexPut() fail %d \n\n", retval);
		}
		return retval;
	}

	int wlFwUseCustomRate(struct net_device *netdev, UINT32 * cust_rate,
			      UINT8 is_set) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_FW_GEN_U32_ACCESS *pCmd =
			(HostCmd_FW_FW_GEN_U32_ACCESS *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HOSTCMD_CMD_SET_CUSTOM_RATE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_FW_GEN_U32_ACCESS));
		pCmd->CmdHdr.macid = 1;
		pCmd->val = *cust_rate;
		pCmd->set = is_set;

		if (wlexecuteCommand(netdev, HOSTCMD_CMD_SET_CUSTOM_RATE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		if (!is_set)
			*cust_rate = pCmd->val;

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		WLDBG_EXIT(DBG_LEVEL_0);

		return SUCCESS;
	}
#endif /* #ifndef SOC_W906X */

	int wlFwSetMcastCtsToSelf(struct net_device *netdev, u8 * enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_SET_MCAST_CTS_TO_SELF *pCmd =
			(HostCmd_SET_MCAST_CTS_TO_SELF *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "wlFwSetMcastCtsToSelf");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_SET_MCAST_CTS_TO_SELF));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_SET_MCAST_CTS_TO_SELF);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_SET_MCAST_CTS_TO_SELF));
		pCmd->enable = ENDIAN_SWAP32(*enable);

		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_SET_MCAST_CTS_TO_SELF);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (retval != SUCCESS)
			printk("\n\n wlFwSetMcastCtsToSelf() fail %d \n\n",
			       retval);

		return retval;
	}

#ifdef AP_STEERING_SUPPORT
	int wlFwGetQBSSLoad(struct net_device *netdev, UINT8 * ch_util,
			    UINT16 * sta_cnt) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_CCA_Busy_Fract *pCmd =
			(HostCmd_FW_GET_CCA_Busy_Fract *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_CCA_Busy_Fract));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_CCA_BUSY_FRACTION);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_CCA_Busy_Fract));

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_GET_CCA_Busy_Fract));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_CCA_BUSY_FRACTION);
		if (!retval) {
			*ch_util = pCmd->ChannelUtil;
			*sta_cnt = pCmd->StaCnt;
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
#endif //AP_STEERING_SUPPORT

#ifdef DSP_COMMAND
#include "dsp_cmd.h"

#ifdef DSP_TRIG_CMD
#include "ap8xLnxSwMimoTypes.h"
#include "ap8xLnxSwMimo.h"
#endif
	int wlDspCmd(struct net_device *netdev, UINT8 index, UINT8 priority,
		     UINT32 * result) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_DSP_CMD *pCmd =
			(HostCmd_DSP_CMD *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_DSP_CMD));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_DSP_CMD);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DSP_CMD));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->cmdIndex = index;
		pCmd->cmdPriority = priority;

		// TBD, compose command
		pCmd->ptrSrcData = wlpptr->wlpd_p->pPhysDspBuf;
		pCmd->ptrDstData =
			wlpptr->wlpd_p->pPhysDspBuf + DSP_BUF_SIZE - 0x1000;
		wlpptr->pDspBuf[0] = 0x151fe9db;
		wlpptr->pDspBuf[1] = 0x485e0d21;
		wlpptr->pDspBuf[2] = 0xd5a0b9ab;
		wlpptr->pDspBuf[3] = 0x0505f8fd;
		pCmd->srcDataLen = 16;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_DSP_CMD));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_DSP_CMD);
		if (!retval)
			*result = pCmd->cmdResult;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

#ifdef DSP_TRIG_CMD
	int wlDspTrig(struct net_device *netdev, UINT8 index, UINT8 priority,
		      UINT8 muGID, UINT8 numUsers, UINT8 pkttype) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_DSP_CMD *pCmd =
			(HostCmd_DSP_CMD *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_DSP_CMD));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_DSP_CMD);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DSP_CMD));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->cmdIndex = index;
		pCmd->cmdPriority = priority;

		// TBD, compose command
		pCmd->ptrSrcData = wlpptr->wlpd_p->pPhysDspBuf;
		pCmd->ptrDstData =
			wlpptr->wlpd_p->pPhysDspBuf + DSP_CMD_BUF_SIZE - 0x1000;

		pCmd->srcDataLen =
			createDspData((U8 *) wlpptr->pDspBuf, muGID, numUsers,
				      pkttype);

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_DSP_CMD));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_DSP_CMD);

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
	int wlDspTrigMu(struct net_device *netdev, UINT8 index, UINT8 priority,
			U8 * msg, int len) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_DSP_CMD *pCmd =
			(HostCmd_DSP_CMD *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;

		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_DSP_CMD));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_DSP_CMD);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_DSP_CMD));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->cmdIndex = index;
		pCmd->cmdPriority = priority;

		// TBD, compose command
		pCmd->ptrSrcData = wlpptr->wlpd_p->pPhysDspBuf;
		pCmd->ptrDstData =
			wlpptr->wlpd_p->pPhysDspBuf + DSP_CMD_BUF_SIZE - 0x1000;

		memcpy(wlpptr->pDspBuf, msg, len);

		pCmd->srcDataLen = len;

		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				sizeof(HostCmd_DSP_CMD));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_DSP_CMD);

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
#endif
#endif /* DSP_COMMAND */

	int wlFwGetRadioStatus(struct net_device *netdev,
			       mvl_status_t * radio_status) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_MVL_RADIO_STATUS *pCmd =
			(HostCmd_FW_GET_MVL_RADIO_STATUS *) & wlpptr->
			pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_MVL_RADIO_STATUS));
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_GET_MVL_RADIO_STATUS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_MVL_RADIO_STATUS));

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_GET_MVL_RADIO_STATUS));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_GET_MVL_RADIO_STATUS);
		if (!retval) {
			memcpy(radio_status, &pCmd->radio_status,
			       sizeof(mvl_status_t));
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwSetBeamChange(struct net_device *netdev, u8 enable) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_BEAM_CHANGE *pCmd =
			(HostCmd_FW_SET_BEAM_CHANGE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		WLDBG_ENTER_INFO(DBG_LEVEL_0, "wlFwSetBeamChange");

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_BEAM_CHANGE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_BEAM_CHANGE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_BEAM_CHANGE));
		pCmd->enable = enable;
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_BEAM_CHANGE);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

#ifdef SOC_W906X

	int wlFwSendFrame(struct net_device *netdev, UINT16 staIdx,
			  UINT8 reportId, UINT8 tid, UINT32 rateInfo,
			  UINT8 machdrLen, UINT16 payloadLen, UINT8 * pMacHdr,
			  UINT8 * pData) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_DS_TX_FRAME_TEST *pCmd =
			(HostCmd_DS_TX_FRAME_TEST *) & wlpptr->pCmdBuf[0];
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);

		memset((void *)pCmd, 0x00, sizeof(HostCmd_DS_TX_FRAME_TEST));

		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_TX_FRAME_TEST);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->status = 0;
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.Length =
			sizeof(HostCmd_DS_TX_FRAME_TEST) - sizeof(pCmd->data);
		pCmd->reportId = reportId;	//0: no report, others: report needed
		pCmd->staIdx = ENDIAN_SWAP16(staIdx);	//0xffff <-- bcast/mcast (0~319)
		pCmd->rateInfo = ENDIAN_SWAP32(rateInfo);
		pCmd->tid = tid;
		pCmd->machdrLen = machdrLen;
		pCmd->payloadLen = payloadLen;

		if (machdrLen && (machdrLen < MAX_TX_FRAME_LEN))
			memcpy(pCmd->data, pMacHdr, machdrLen);

		if (payloadLen && ((payloadLen + machdrLen) < MAX_TX_FRAME_LEN))
			memcpy(&pCmd->data[machdrLen], pData, payloadLen);

		pCmd->CmdHdr.Length += machdrLen + payloadLen;

		pCmd->payloadLen = ENDIAN_SWAP16(pCmd->payloadLen);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(pCmd->CmdHdr.Length);
		WLDBG_INFO(DBG_LEVEL_0, "wlFwSendTxTest Command Request:::\n");
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				ENDIAN_SWAP16(pCmd->CmdHdr.Length));

		if (wlexecuteCommand(netdev, HostCmd_CMD_TX_FRAME_TEST)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		WLDBG_INFO(DBG_LEVEL_0,
			   "wlFwSendTxTest Command Response :::\n");
		WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)pCmd,
				ENDIAN_SWAP16(pCmd->CmdHdr.Length));

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return pCmd->status;
	}

	int wlFwGetTsf(struct net_device *netdev, tsf_info_t * ptsf) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_TSF *pCmd =
			(HostCmd_FW_GET_TSF *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		u8 macid = wlpptr->vmacSta_p->VMacEntry.macId;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_TSF));

		pCmd->CmdHdr.macid = macid;
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_PARENT_TSF);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_TSF));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_GET_TSF));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_PARENT_TSF);

		if (!retval) {
			memcpy((void *)ptsf, (void *)&pCmd->tsfInfo,
			       sizeof(tsf_info_t));
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		//printk("Get macid:%u hwtsf:%16llx, bsstsfBase:%16llx, bsstsf:%16llx\n", macid, ptsf->HwTsfTime, ptsf->BssTsfBase, ptsf->BssTsfTime);
		return retval;
	}

// New added CB ++
#ifdef CB_SUPPORT
	int wlFwSetApCBMode(struct net_device *netdev, u8 mode) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
		HostCmd_AP_CBMODE *pCmd =
			(HostCmd_AP_CBMODE *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		u8 macid = wlpptr->vmacSta_p->VMacEntry.macId;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_AP_CBMODE));

		pCmd->CmdHdr.macid = macid;
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_AP_CBMODE);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_AP_CBMODE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		pCmd->mode = mode;

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_AP_CBMODE));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_AP_CBMODE);

		if (!retval) {
			printk("Set AP cb mode done\n");
		}
		parent_wlpptr->bcnBasePtr = pCmd->bcnBasePtr;
		printk("=>cmd: bcnBasePtr: %x\n", pCmd->bcnBasePtr);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwSetStaCBNoAck(struct net_device *netdev, u8 staid, u8 mode) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_STA_CB_NOACK *pCmd =
			(HostCmd_STA_CB_NOACK *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		u8 macid = wlpptr->vmacSta_p->VMacEntry.macId;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_STA_CB_NOACK));

		pCmd->CmdHdr.macid = macid;
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_STA_CB_NOACK);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_STA_CB_NOACK));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		pCmd->staid = staid;
		pCmd->mode = mode;
		//printk("==> %s():\n", __func__);
		//mwl_hex_dump((void*)pCmd, sizeof(HostCmd_STA_CB_NOACK));
		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_STA_CB_NOACK));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_SET_STA_CB_NOACK);

		if (!retval) {
			printk("Set AP cb noack done\n");
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwGetStaCBParam(struct net_device *netdev,
			      HostCmd_STA_CB_PARAMS_SYNC * psta_cb_param) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_STA_CB_PARAMS_SYNC *pCmd =
			(HostCmd_STA_CB_PARAMS_SYNC *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		u8 macid = wlpptr->vmacSta_p->VMacEntry.macId;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_STA_CB_PARAMS_SYNC));

		pCmd->CmdHdr.macid = macid;
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_GET_STA_CB_PARAMS_SYNC);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_STA_CB_PARAMS_SYNC));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		pCmd->staid = psta_cb_param->staid;

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_STA_CB_PARAMS_SYNC));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_GET_STA_CB_PARAMS_SYNC);

		if (!retval) {
			//memcpy(psn, pCmd->sn, sizeof(u16)*8);
			memcpy(psta_cb_param, pCmd,
			       sizeof(HostCmd_STA_CB_PARAMS_SYNC));
			//printk("Get sta cb param done\n");
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

	int wlFwSetStaCBParam(struct net_device *netdev,
			      HostCmd_STA_CB_PARAMS_SYNC * psta_cb_param) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_STA_CB_PARAMS_SYNC *pCmd =
			(HostCmd_STA_CB_PARAMS_SYNC *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;
		u8 macid = wlpptr->vmacSta_p->VMacEntry.macId;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_STA_CB_PARAMS_SYNC));

		pCmd->CmdHdr.macid = macid;
		pCmd->CmdHdr.Cmd =
			ENDIAN_SWAP16(HostCmd_CMD_SET_STA_CB_PARAMS_SYNC);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_STA_CB_PARAMS_SYNC));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		// Set the parameters of HostCmd_STA_CB_PARAMS_SYNC
		pCmd->staid = psta_cb_param->staid;
		pCmd->pwrState = psta_cb_param->pwrState;
		memcpy(pCmd->sn, psta_cb_param->sn, sizeof(U16) * 8);
		pCmd->euMode = psta_cb_param->euMode;
		memcpy(pCmd->keyId, psta_cb_param->keyId, sizeof(U8) * 2);
		memcpy(pCmd->pn, psta_cb_param->pn, sizeof(U8) * 16);
		memcpy(pCmd->key, psta_cb_param->key, sizeof(U32) * 2 * 8);
		pCmd->keyRecIdx = psta_cb_param->keyRecIdx;
		pCmd->pn_inc = psta_cb_param->pn_inc;

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_STA_CB_PARAMS_SYNC));
		retval = wlexecuteCommand(netdev,
					  HostCmd_CMD_SET_STA_CB_PARAMS_SYNC);

		if (!retval) {
			printk("Set sta cb param done\n");
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);

		return retval;
	}

#endif //CB_SUPPORT
// New added CB ++

//twt
#ifdef AP_TWT
	extern u32 wfa_twt_rxing_flag_addr;
	int wlFwTwtParam(struct net_device *netdev, UINT8 action, UINT8 * mac,
			 UINT8 agid, twt_param_t * param) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_DS_TWT_PARAM *pCmd =
			(HostCmd_FW_DS_TWT_PARAM *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_DS_TWT_PARAM));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_TWT_PARAM);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_DS_TWT_PARAM));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);

		pCmd->Action = action;	//0:get, 1:set, 2: remove(reset)
		memcpy(pCmd->Stamac, mac, 6);
		pCmd->flowid = agid;

		if (action == WL_SET && param) {
			memcpy((void *)&pCmd->twtparam, (void *)param,
			       sizeof(twt_param_t));
		}

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_DS_TWT_PARAM));

		retval = wlexecuteCommand(netdev, HostCmd_CMD_TWT_PARAM);

		if (!retval) {

			if (action == WL_GET && param) {
				memcpy((void *)param, (void *)&pCmd->twtparam,
				       sizeof(twt_param_t));
			}
#ifdef AP_TWT
			//WAR WFA TWT cases. Geting a DMEM flag to notice PFW of TWT Rxing is running 
			if (wfa_twt_rxing_flag_addr == 0) {
#if 0				//code for DMEM direct acess.
				if ((pCmd->IsTWTRxRunningAddr & 0xff000000) ==
				    0x20000000) {
					wfa_twt_rxing_flag_addr =
						(pCmd->
						 IsTWTRxRunningAddr) & 0xFFFFFF;
					printk("[TWT]: WFA PF Rx Monitor flag Addr:0x%x\n", pCmd->IsTWTRxRunningAddr);
				} else {
					//need to check where the flag is located. if not in DMEM, it might not work.
					printk("[Warning]: PFW TWT for WFA PF flag might not work...\n");
				}
#else
				wfa_twt_rxing_flag_addr =
					pCmd->IsTWTRxRunningAddr;
				printk("[TWT]: WFA PF Rx Monitor flag Addr:0x%x\n", pCmd->IsTWTRxRunningAddr);
#endif
			}
#endif
		}

		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}
#endif

/*Function to set spatial reuse param*/
	int wlFw_SetSR(struct net_device *netdev, UINT8 enable,
		       SINT8 thresNonSrg, SINT8 thresSrg) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_SR *pCmd =
			(HostCmd_FW_SET_SR *) & wlpptr->pCmdBuf[0];
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_SR));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SR_PARAM);
		pCmd->CmdHdr.Length = ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_SR));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->srEnable = enable;
		pCmd->thresNonSrg = thresNonSrg;
		pCmd->thresSrg = thresSrg;

		printk("enable flag:%d, non-SRG thres %d, SRG thres %d\n",
		       pCmd->srEnable, pCmd->thresNonSrg, pCmd->thresSrg);

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_SET_SR));

		retval = wlexecuteCommand(netdev, HostCmd_CMD_SR_PARAM);
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwGetStaStats(struct net_device *netdev, int staId,
			    SMAC_STA_STATISTICS_st * sta_stats) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_GET_STA_STATS *pCmd =
			(HostCmd_FW_GET_STA_STATS *) wlpptr->pCmdBuf;
		int retval = FAIL;
		unsigned long flags;

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_GET_STA_STATS));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_GET_STA_STATS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_GET_STA_STATS));
		pCmd->StaId = staId % sta_num;

		WLDBG_DUMP_DATA(DBG_LEVEL_1, (void *)pCmd,
				sizeof(HostCmd_FW_GET_STA_STATS));
		retval = wlexecuteCommand(netdev, HostCmd_CMD_GET_STA_STATS);
		if (!retval) {
			memcpy(sta_stats, &pCmd->StaStats,
			       sizeof(SMAC_STA_STATISTICS_st));
		}
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		return retval;
	}

	int wlFwSetOFDMASet(struct net_device *netdev, UINT8 enable,
			    UINT8 sta_count, UINT16 * Stn) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_OFDMA_SET *pCmd =
			(HostCmd_FW_SET_OFDMA_SET *) & wlpptr->pCmdBuf[0];
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		MIB_802DOT11 *mib;
		unsigned long flags;
		u16 result;

		WLDBG_ENTER(DBG_LEVEL_0);

		if (vmacSta_p->master) {
			vmacSta_p = vmacSta_p->master;
		}
		mib = vmacSta_p->Mib802dot11;
		if ((mib->DL_ofdma_enable == 0) && enable) {
			return SUCCESS;
		}

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_OFDMA_SET));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_OFDMA_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_OFDMA_SET));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = 1;
		pCmd->Option = enable;
		pCmd->sta_count = sta_count;

		if (Stn && sta_count)	//Stn might be null for Del Mu Set
			memcpy(&pCmd->StnID[0], Stn, sizeof(pCmd->StnID));

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_OFDMA_SET)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return SUCCESS;
		else
			return FAIL;
	}

	int wlFwSetULMUSet(struct net_device *netdev, UINT8 Action,
			   UINT32 RateInfo, UINT32 Flag, UINT8 GID, UINT8 Mode,
			   UINT8 BandWidth, UINT8 StaNum,
			   ul_stnid_ru_t * StaList) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_ULMU_SET *pCmd =
			(HostCmd_FW_SET_ULMU_SET *) & wlpptr->pCmdBuf[0];
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
		MIB_802DOT11 *mib;
		u16 result;
		unsigned long flags;

		if (vmacSta_p->master) {
			vmacSta_p = vmacSta_p->master;
		}
		mib = vmacSta_p->Mib802dot11;
		if ((mib->UL_mimo_enable == 0) && Action == HostCmd_ACT_GEN_SET
		    && Mode == 1) {
			/* Mode == 1 is MIMO */
			return SUCCESS;
		} else if ((mib->UL_ofdma_enable == 0) &&
			   Action == HostCmd_ACT_GEN_SET && Mode == 2) {
			/* Mode == 2 is OFDMA */
			return SUCCESS;
		}

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_ULMU_SET));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_ULMU_SET);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_ULMU_SET) -
				      (sizeof(ul_stnid_ru_t) *
				       (MU_MAX_USERS - StaNum)));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->Action = Action;
		pCmd->Version = 0;
		pCmd->RateInfo = ENDIAN_SWAP32(RateInfo);
		pCmd->Flag = ENDIAN_SWAP32(Flag);
		pCmd->GID = ENDIAN_SWAP16(GID);
		pCmd->Mode = Mode;
		pCmd->BandWidth = BandWidth;
		pCmd->StaNum = StaNum;

		if (Action == HostCmd_ACT_GEN_SET) {
			memcpy(pCmd->StaList, StaList,
			       sizeof(ul_stnid_ru_t) * (StaNum));
		}

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_ULMU_SET)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return SUCCESS;
		else
			return FAIL;
	}

	int wlFwSetAcntWithMu(struct net_device *netdev, UINT16 Action) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_ANCT_WITH_MU *pCmd =
			(HostCmd_FW_SET_ANCT_WITH_MU *) & wlpptr->pCmdBuf[0];
		u16 result;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_ULMU_SET));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_ANCT_WITH_MU);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_ANCT_WITH_MU));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->Action = ENDIAN_SWAP16(Action);

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_ANCT_WITH_MU)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return SUCCESS;
		else
			return FAIL;
	}

	int wlFwSetSTAawake(struct net_device *netdev, UINT16 Action,
			    UINT16 stnid, UINT16 forceAwake) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_SET_STA_AWAKE *pCmd =
			(HostCmd_FW_SET_STA_AWAKE *) & wlpptr->pCmdBuf[0];
		u16 result;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);

		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_SET_STA_AWAKE));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_SET_STA_AWAKE);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_SET_STA_AWAKE));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->Action = ENDIAN_SWAP16(Action);
		pCmd->stnid = stnid;
		pCmd->forceAwake = (forceAwake ? 1 : 0);

		if (wlexecuteCommand(netdev, HostCmd_CMD_SET_STA_AWAKE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return SUCCESS;
		else
			return FAIL;
	}

	int wlFwDFSParams(struct net_device *netdev, UINT16 Action,
			  UINT8 * fcc_min_radar_num_pri,
			  UINT8 * etsi_min_radar_num_pri,
			  UINT8 * jpn_w53_min_radar_num_pri,
			  UINT8 * jpn_w56_min_radar_num_pri,
			  UINT8 * false_detect_th, UINT8 * fcc_zc_error_th,
			  UINT8 * etsi_zc_error_th, UINT8 * jp_zc_error_th) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		HostCmd_FW_DFS_PARAMS *pCmd =
			(HostCmd_FW_DFS_PARAMS *) & wlpptr->pCmdBuf[0];
		u16 result;
		u8 i;
		unsigned long flags;

		WLDBG_ENTER(DBG_LEVEL_0);
		MWL_SPIN_LOCK(&wlpptr->wlpd_p->locks.fwLock);
		memset(pCmd, 0x00, sizeof(HostCmd_FW_DFS_PARAMS));
		pCmd->CmdHdr.Cmd = ENDIAN_SWAP16(HostCmd_CMD_DFS_PARAMS);
		pCmd->CmdHdr.Length =
			ENDIAN_SWAP16(sizeof(HostCmd_FW_DFS_PARAMS));
		pCmd->CmdHdr.SeqNum = GET_CMD_SEQ_NUM(wlpptr);
		pCmd->CmdHdr.macid = wlpptr->vmacSta_p->VMacEntry.macId;
		pCmd->Action = ENDIAN_SWAP16(Action);
		for (i = 0;
		     i < (sizeof(pCmd->fcc_min_radar_num_pri) / sizeof(u8));
		     i++) {
			pCmd->fcc_min_radar_num_pri[i] =
				fcc_min_radar_num_pri[i];
		}
		for (i = 0;
		     i < (sizeof(pCmd->etsi_min_radar_num_pri) / sizeof(u8));
		     i++) {
			pCmd->etsi_min_radar_num_pri[i] =
				etsi_min_radar_num_pri[i];
		}
		for (i = 0;
		     i < (sizeof(pCmd->jpn_w53_min_radar_num_pri) / sizeof(u8));
		     i++) {
			pCmd->jpn_w53_min_radar_num_pri[i] =
				jpn_w53_min_radar_num_pri[i];
		}
		for (i = 0;
		     i < (sizeof(pCmd->jpn_w56_min_radar_num_pri) / sizeof(u8));
		     i++) {
			pCmd->jpn_w56_min_radar_num_pri[i] =
				jpn_w56_min_radar_num_pri[i];
		}
		pCmd->false_detect_th = *false_detect_th;
		pCmd->fcc_zc_error_th = *fcc_zc_error_th;
		pCmd->etsi_zc_error_th = *etsi_zc_error_th;
		pCmd->jp_zc_error_th = *jp_zc_error_th;

		if (wlexecuteCommand(netdev, HostCmd_CMD_DFS_PARAMS)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_0, "failed execution");
			MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
			return FAIL;
		}

		if (Action == DFS_GET_ALL) {
			for (i = 0;
			     i <
			     (sizeof(pCmd->fcc_min_radar_num_pri) / sizeof(u8));
			     i++) {
				fcc_min_radar_num_pri[i] =
					pCmd->fcc_min_radar_num_pri[i];
			}
			for (i = 0;
			     i <
			     (sizeof(pCmd->etsi_min_radar_num_pri) /
			      sizeof(u8)); i++) {
				etsi_min_radar_num_pri[i] =
					pCmd->etsi_min_radar_num_pri[i];
			}
			for (i = 0;
			     i <
			     (sizeof(pCmd->jpn_w53_min_radar_num_pri) /
			      sizeof(u8)); i++) {
				jpn_w53_min_radar_num_pri[i] =
					pCmd->jpn_w53_min_radar_num_pri[i];
			}
			for (i = 0;
			     i <
			     (sizeof(pCmd->jpn_w56_min_radar_num_pri) /
			      sizeof(u8)); i++) {
				jpn_w56_min_radar_num_pri[i] =
					pCmd->jpn_w56_min_radar_num_pri[i];
			}

			*false_detect_th = pCmd->false_detect_th;
			*fcc_zc_error_th = pCmd->fcc_zc_error_th;
			*etsi_zc_error_th = pCmd->etsi_zc_error_th;
			*jp_zc_error_th = pCmd->jp_zc_error_th;
		}

		result = pCmd->CmdHdr.Result;
		MWL_SPIN_UNLOCK(&wlpptr->wlpd_p->locks.fwLock);
		if (result == HostCmd_RESULT_OK)
			return SUCCESS;
		else
			return FAIL;
	}

#endif
