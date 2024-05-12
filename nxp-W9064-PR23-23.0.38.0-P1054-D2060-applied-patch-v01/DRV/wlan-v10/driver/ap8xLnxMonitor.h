/** @file ap8xLnxMonitor.h
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
#ifndef AP8X_MONITOR_H_
#define AP8X_MONITOR_H_
#include "wltypes.h"
#include "smac_hal_inf.h"

extern int register_wlmon_notifier(void *wlpd);
extern int unregister_wlmon_notifier(void *wlpd);

extern int start_wlmon(void *wlp);
extern int stop_wlmon(void *wlp);

#define  NUM_SFWTX_CHK_POINTS	6
#define  NUM_SFWTX_RECORDS		4

#define  NUM_SFWRX_CHK_POINTS	5
#define  NUM_SFWRX_RECORDS		4

#define  BCN_STUCK_THRESHOLD    5000	//ms

//trigger threshold for launch PFW shedule delay event
#define PFW_SCHEDULE_DELAY      10000	//us

#define HM_CMD_RESP_THRESHOLD    500000	//500ms

#define PFW_ALIVE_CNT_OFFSET	 0xb0	//this value depend on hal_hiu.h in PFW
#define PFW_ALIVE_THRESHOLD      3
#define SMACSTATUS_LOG_MAX_LENGTH 5120

#define MON_SMAC_STUCK        (1<<0)
#define MON_SMAC_BCN_STUCK    (1<<1)
#define MON_SMAC_TX_STUCK     (1<<2)
#define MON_SMAC_RX_STUCK     (1<<3)
#define MON_PFW_ALIVE_CNTS    (1<<4)
#define MON_PFW_SCHE_INFO     (1<<5)
#define MON_DRV_ERR_CNTS      (1<<6)
#define MON_DRV_BMQ_RESOURCE  (1<<7)
#define MON_DRV_CMD			  (1<<8)
#define MON_FW_AUTO_RECOVERY  (1<<9)
#define MON_MOCHI_ERROR		  (1<<10)
#define MON_TEMPERATURE       (1<<11)
#define MON_MEM_USAGE         (1<<12)
#define MON_RECOVERY_DETECT   (1<<13)

#define WLMON_DEFAULT_DISABLE    0
#define WLMON_DEFAULT_ENABLE     1

#define WLMON_DEFAULT_HMMASK     (MON_SMAC_STUCK|MON_SMAC_BCN_STUCK|MON_SMAC_RX_STUCK|MON_PFW_ALIVE_CNTS|MON_DRV_ERR_CNTS|MON_DRV_BMQ_RESOURCE|MON_DRV_CMD|MON_MOCHI_ERROR|MON_TEMPERATURE)
#define WLMON_DEFAULT_TEMPERATURE_THRESHOLD  90
#define WLMON_DEFAULT_TEMPERATURE_THRESHOLD_HOST  90

#define SMAC_STATUS_FORMAT_RAW	(1<<0)
#define SMAC_STATUS_FORMAT_TXT	(1<<1)

#define MAX_SMACSTATUS_LOG_ENTRY  5
#define MAX_TXSCHSTATE_LOG_ENTRY  MAX_SMACSTATUS_LOG_ENTRY

typedef struct {
	UINT64 ts;		//the last refill timestamp
	UINT64 tsivl;		//time period of this measuring period
	UINT32 buffcnt;		//total buffer counter during measuring this period
	UINT32 refillcnt;	//total refill times during the measuring period
	UINT32 lastbuffcnt;	//refill buff counts at the last refill. 
} bmq_refill_info;

typedef struct {
	UINT32 alivecnt[MAX_SMACSTATUS_LOG_ENTRY];	//log the last access pfw alive counter
	UINT32 stuckcnt;	//log # of no change that has been check
} pfw_alive_cnter;

#define DELAY_COREDUMP_TIME      (3)

#define HM_CMDBUF_SIZE   512	//buffer to keep last executed cmd.

typedef struct {
	u64 TxScheStateInfoTimestamp;
	u32 RangeIdx[2];
	u32 int_stat2[200][8];
} tx_internal_state2;

#define MAX_STADB_BUFF_SIZE   (1024*16)
typedef struct {
	u64 StaDbTimestamp;
	u8 StaDbBuf[MAX_STADB_BUFF_SIZE];
} sta_db_snap;

#define MAX_INVALID_ADDR_HOLE 32
typedef struct _inv_addr_hole_ {
	u32 num;
	u32 addr[MAX_INVALID_ADDR_HOLE][2];
} invalid_addr_hole;

typedef struct _host_thermal_chan_load {
	UINT64 timestamp;
	UINT32 host_temp;	//host temperatrure
	UINT32 radio_temp;	//radio temperature
	UINT32 chan_load;
} host_thm_chan_load_t;

#define TX_SCHE_INTERNAL_STATE_ENTRY_SIZE  sizeof(tx_internal_state2)
#define TX_SCHE_INTERNAL_STATE_POOL_SIZE   (TX_SCHE_INTERNAL_STATE_ENTRY_SIZE*MAX_SMACSTATUS_LOG_ENTRY)

typedef struct {
	UINT32 cm_heartbit[SMAC_CPU_NUM];	//last hearbit values of cm3_0 - cm3_6  
	UINT8 cm_stuckcnt[SMAC_CPU_NUM];	//cm3_x consecutive hearbit stuck counters
	UINT8 active;		//smac monitor active flag.
	UINT8 ready;		// wlmon_kthread initialized
	UINT8 exceptionEvt_rcvd;	//exception event received from PFW. PFW was already in coredumpmode
	UINT8 parityErrEvt_rcvd;
	UINT8 exceptionCmdTOEvt_rcvd;	//cmd timeout event detected
	UINT8 exceptionAbortCmdExec;	//flag to denote aborting cmd execution
	UINT8 exceptionDelayCoreDumpCnt;	//counter for delaying coredump
	UINT32 cpu_parity_check_status;
	struct blocking_notifier_head wlmon_notifier_list;
	struct notifier_block *nb;
	void *pexcept_cnt;	//pbuf to keep old exception statistic counters.
	UINT8 *piocmdlog;	//pbuf to log ioctls and fw cmds
	UINT32 cmdlogidx;
	UINT32 ActiveBitmap;	//bitmap to enable the monitoring events.

	UINT8 *psmacStatus;	//pbuf to log SMAC_STATUS_st. There are 2*sizeof(SMAC_STATUS_st) allocated. timetick are stored in SMAC_STATUS_st->rsvd[0-7]  
	UINT8 *psmacWarningLog[MAX_SMACSTATUS_LOG_ENTRY];
	UINT8 *psmacScheduleInfo[MAX_SMACSTATUS_LOG_ENTRY];
	UINT8 *psmacPktcnt[MAX_SMACSTATUS_LOG_ENTRY];
	UINT8 *psmacGenInfo[MAX_SMACSTATUS_LOG_ENTRY];
	UINT64 smacStsLogtime[2];	//record the timestamp at psmacStatus is retrieved.
	UINT32 ActVapBitmap;	//bitmap to store active VAP. 
	UINT32 lastActVapBitmap;	//bitmap to store last active VAP.
	UINT8 *psmacStatusLog;	//log buffer of smac status for log out immediately before coredump/reset. 
	UINT32 smacStatusLogIdx;	//index to store next entry
	UINT64 smacStsTimestamp[MAX_SMACSTATUS_LOG_ENTRY];

	UINT8 *pStaDbTable;	//table to keep last sample of sta db
	UINT8 *pLastCmdBuf;	//buffer to keep the last cmd sent to pfw

	UINT8 bcnstuckcnt[SMAC_BSS_NUM];	//counter to cnt bcn stuck 
	UINT64 bcnstucktimestamp[SMAC_BSS_NUM];	//bcn stuck since timestamp(ms) 

	UINT8 ActiveIf;		//record active interface bitmap;
	UINT32 TxPktIdx;	//next index to log TxPktDiff
	UINT32 TxPktDiff[NUM_SFWTX_RECORDS][NUM_SFWTX_CHK_POINTS];	//log the tx pkt increase of the last 4 checking
	UINT32 RxPktIdx;
	UINT32 RxPktDiff[NUM_SFWRX_RECORDS][NUM_SFWRX_CHK_POINTS];	//log the rx pkt increase of the last 4 checking
	bmq_refill_info bmqInfo[3];	//record BMQ 10/11/12 last refill timestamp

	UINT32 MochiErrCnt;	//log mochi error monitor counter
	void *pPFWSchInfo;	//pbuf to log PFW scheduler Info 
	//UINT32  pfwSchIndex;                                                                            //next index to log PFW scheduler Info

	UINT8 bcnstuck_st;	//flag to denote bcn stuck already hit or not
	UINT8 txstuck_st;	//flag to denote tx stuck already hit or not
	UINT8 rxstuck_st;	//flag to denote tx stuck already hit or not
	UINT8 pfwidx;		//index of the record that has the max delay   
	UINT32 maxschdelay;	//max delay value

	pfw_alive_cnter pfwaliveCnt[3];	//0:cmd_thread_alive, 1:sche_thread_alive, 2:idle_thread_alive
	char dumpstsname[96];	//file name of dump sts log
	char dumpcmdname[48];	//file name of dump cmd log

	UINT32 temperature_threshold;
	UINT32 temperature_threshold_host;

	host_thm_chan_load_t thm_chanload[MAX_SMACSTATUS_LOG_ENTRY];
	UINT32 thm_chanload_idx;

	UINT32 smacStatusFormat;
} smac_mon;

#endif /* AP8X_MONITOR_H_ */
