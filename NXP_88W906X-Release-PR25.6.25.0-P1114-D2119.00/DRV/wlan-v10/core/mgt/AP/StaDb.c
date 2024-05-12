/** @file StaDb.c
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

/*****************************************************************************
*
* $HEADER$
*
* Purpose:
*    This file contains the implementation of the table that contains
*    information about external stations, including their MAC address,
*    power mode, and a state that indicates the current relationship
*    to the station using this table.
*
* Public Procedures:
*    extStaDb_AddSta      Add a station to the table
*    extStaDb_DelSta      Delete a station from the table
*    extStaDb_SetState    Set the state of an external station
*    extStaDb_GetState    Get the state of an external station
*
* Private Procedures:
*    LocateAddr           Looks for a given MAC address in the table
*    Hash                 Returns an index based on a hashing function call
*
* Notes:
*    None.
*
*****************************************************************************/

/*!
* \file    StaDb.c
* \brief   Stations Data Info Database module
*/
/*============================================================================= */
/*                               INCLUDE FILES */
/*============================================================================= */
//#include <stdlib.h>
#include "ap8xLnxIntf.h"
#include "wltypes.h"

#include "IEEE_types.h"
#include "mib.h"
#include "ds.h"
#include "osif.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "wldebug.h"

#include "qos.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
//#include "macpriv.h"
#include "List.h"
#include "idList.h"
#include "mhsm.h"
#include "buildModes.h"
#include "ap8xLnxFwcmd.h"


#ifdef USE_NEW_OSIF
SEM_HANDLE staSH;
SEM_HANDLE EthstaSH;
#else
#define staSH sysinfo_EXT_STA_SEM
#endif

/*============================================================================= */
/*                                DEFINITIONS */
/*============================================================================= */

/* */
/* Chosen as an optimal table size such that not too much memory is */
/* used up and hashing collisions are not overly frequent */
/* */

/*============================================================================= */
/*                              TYPE DEFINITIONS */
/*============================================================================= */

/* */
/* List elements that include information on an external station. */
/* */

/*============================================================================= */
/*                          MODULE LEVEL VARIABLES */
/*============================================================================= */

/* */
/* define the aging time */
/* */

/* */
/* Indicates if the database has been initialized */
/* */

/* */
/* An array of elements to store information on external stations */
/* */

/* */
/* The hash table; information on external stations is stored based on */
/* their MAC address. Since the MAC address is not a suitable index into */
/* an array of external stations, the address is input into a hashing */
/* function that returns a suitable index into the table. The size of the */
/* table has tradeoffs - the bigger it is, less collisions will occur */
/* from the hash function, but more memory will be used. The smaller it */
/* is, more collisions will occur, but less memory will be used. Each */
/* element in the hash table is a pointer to a list element that is used */
/* to store the information on the external station; if collisions occur */
/* for a given location in the hash table, then a list element is added */
/* to the element or elements already assigned to that location. */
/* */

/*------------------------------------------------------------------------*/
/* The following is a table used to determine if a requested state change */
/* of an external station is admissable, relative to the state currently  */
/* stored for that external station. The table is a square two            */
/* dimensional array where each row and column is associated with the     */
/* states given by the extStaDb_State_e enumeration type. Each column     */
/* represents a state currently stored for an external station; each row  */
/* represents a state requested to transition to. Hence, if the current   */
/* state is UNAUTHENTICATED, and a request made to transition to          */
/* ASSOCIATING state, the table indicates this is not admissable since    */
/* that entry in the table indicates NOT_AUTHENTICATED. Admissable        */
/* transitions are indicated by STATE_SUCCESS. It should be noted that    */
/* states dealing with association on apply to external stations that are */
/* also APs. The table does not check pertaining to APs vs. stations -    */
/* for example, it makes no sense to have stations associated with each   */
/* other. These checks must be made without the use of the table, which   */
/* is only used to verify state transitions.                              */
/*------------------------------------------------------------------------*/
/*============================================================================= */
/*                   PRIVATE PROCEDURES (ANSI Prototypes) */
/*============================================================================= */
static extStaDb_Status_e LocateAddr(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr_p, ExtStaInfoItem_t ** Item_p, UINT32 * Idx_p);
static UINT32 Hash(UINT32 key);
static UINT32 Jenkins32BitMix(UINT32 key);
/*static UINT32 Wang32BitMix( UINT32 key ); */
/*============================================================================= */
/*                         CODED PUBLIC PROCEDURES */
/*============================================================================= */
extern void UpdateAssocStnData(UINT8 Aid, UINT8 ApMode);
extern void macMgmtMlme_DecrBonlyStnCnt(vmacApInfo_t * vmacSta_p, UINT8);
extern void macMgmtMlme_DecrBarkerPreambleStnCnt(vmacApInfo_t * vmacSta_p);
extern void FreePowerSaveQueue(UINT32 StnId);
extern void ProcessKeyMgmtData(vmacApInfo_t * vmacSta_p, void *, IEEEtypes_MacAddr_t *, MhsmEvent_t *);
void extStaDb_ProcessAgeTick(UINT8 * data);
void ethStaDb_ProcessAgeTick(UINT8 * data);

int send_11n_aggregation_skb(struct net_device *netdev, extStaDb_StaInfo_t * pStaInfo, int force);
#ifdef WDS_FEATURE
void RemoveWdsPort(vmacApInfo_t * vmacSta_p, UINT8 * macAddr);
#endif
extern void CleanCounterClient(vmacApInfo_t * vmacSta_p);
extern void ClientStatistics(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * pStaInfo);
extern void HandleNProtectionMode(vmacApInfo_t * vmacSta_p);
extern void cleanupAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr);
extern void ap8xLnxStat_clients_WQadd(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * addr_p, UINT8 Hdlr);

#ifdef FLEX_TIME
UINT8 BGOnlyClientCnt = 0;/** use only in agflex mode **/
UINT8 AOnlyClientCnt = 0;
#endif

#ifdef STADB_IN_CACHE
static extStaDb_StaInfo_t *extStaDb_GetCachedStaInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	if (!vmac_p->lru_stadb)
		goto not_found;

	if (ether_addr_equal(vmac_p->lru_stadb->Addr, (UINT8 *) Addr_p))
		return vmac_p->lru_stadb;

 not_found:
	return NULL;
}

static void extStaDb_DelCachedStaInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	if (!vmac_p->lru_stadb)
		return;

	if (ether_addr_equal(vmac_p->lru_stadb->Addr, (UINT8 *) Addr_p))
		vmac_p->lru_stadb = NULL;

	return;
}

static void extStaDb_UpdateCachedStaInfo(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * StaInfo_p)
{
	vmac_p->lru_stadb = StaInfo_p;
}
#endif				/* STADB_IN_CACHE */

/******************************************************************************
*
* Name: extStaDb_Init
*
* Description:
*    Routine to initial the structures used in the external stations table.
*
* Conditions For Use:
*    None.
*
* Arguments:
*    None.
*
* Return Value:
*    Status indicating success or failure.
*
* Notes:
*    None.
*
* PDL:
*    Initialize the array of pointers to station elements to NULL
*    Set up the list of free structures which will be used to store
*       information on external stations
*    Initialized the semaphore used to govern access to the table
*    Set the initialized flag to true
*    Return success status
* END PDL
*
*****************************************************************************/
/*!
* Station database initialization 
*/
extern WL_STATUS extStaDb_Init(vmacApInfo_t * vmacSta_p, UINT16 MaxStns)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	UINT32 i;
	if (vmacSta_p->master)
		return (OS_SUCCESS);
	if (vmacSta_p->StaCtl == NULL) {
		vmacSta_p->StaCtl = (struct STADB_CTL *)wl_kmalloc_autogfp(sizeof(struct STADB_CTL));
		if (vmacSta_p->StaCtl == NULL) {
			printk("fail to alloc memory\n");
			return OS_FAIL;
		}
		memset(vmacSta_p->StaCtl, 0, sizeof(struct STADB_CTL));
	}

	vmacSta_p->StaCtl->MaxStaSupported = MaxStns;
	vmacSta_p->StaCtl->aging_time_in_minutes = 3 * 60 / AGING_TIMER_VALUE_IN_SECONDS;

	/*pre-allocate sta datebase */
	if (vmacSta_p->StaCtl->ExtStaInfoDb == NULL) {
		vmacSta_p->StaCtl->ExtStaInfoDb = (ExtStaInfoItem_t *) wl_kmalloc_autogfp(MaxStns * sizeof(ExtStaInfoItem_t));
		if (vmacSta_p->StaCtl->ExtStaInfoDb == NULL) {
			printk("fail to alloc memory\n");
			return OS_FAIL;
		}
		memset(vmacSta_p->StaCtl->ExtStaInfoDb, 0, MaxStns * sizeof(ExtStaInfoItem_t));
	}

	/*Allocate memory for station MU capabilities */
	if (vmacSta_p->StaCtl->MUStaDb == NULL) {
		vmacSta_p->StaCtl->MUStaDb = (MUCapStaNode_t *) wl_kmalloc_autogfp(MaxStns * sizeof(MUCapStaNode_t));
		if (vmacSta_p->StaCtl->MUStaDb == NULL) {
			printk("fail to alloc memory for MU Cap\n");
			return OS_FAIL;
		}
		memset(vmacSta_p->StaCtl->MUStaDb, 0, MaxStns * sizeof(MUCapStaNode_t));
	}

	/*----------------------------------------------------------------*/
	/* Initial the array of pointers to station information elements; */
	/* initially, the pointers all point to nothing.                  */
	/*----------------------------------------------------------------*/
	for (i = 0; i < EXT_STA_TABLE_SIZE_RUNNING; i++) {
		vmacSta_p->StaCtl->ExtStaInfoDb_p[i] = NULL;
	}

	ListInit(&vmacSta_p->StaCtl->FreeStaList);
	ListInit(&vmacSta_p->StaCtl->StaList);
	ListInit(&vmacSta_p->StaCtl->FreeMUStaList);
	MUSetListInit(&wlpptr->wlpd_p->MUSetList);

	/*-------------------------------------------------------------*/
	/* Set up the list of initially free elements that are used to */
	/* record external station information.                        */
	/*-------------------------------------------------------------*/
	for (i = 0; i < MaxStns; i++) {
		vmacSta_p->StaCtl->ExtStaInfoDb[i].nxt = NULL;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].prv = NULL;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].nxt_ht = NULL;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].prv_ht = NULL;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.AP = FALSE;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.State = UNAUTHENTICATED;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.PwrMode = PWR_MODE_ACTIVE;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.TimeStamp = 30;
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.ClientMode = 0;
#ifdef SOC_W906X
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.StnId = sta_num;
#endif
		memset(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.Addr, 0, sizeof(IEEEtypes_MacAddr_t));
		vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.pn = wl_kmalloc(sizeof(rx_pn_info_t), GFP_KERNEL);
		if (vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.pn == NULL) {
			printk("fail to alloc memory for station db pn entry\n");
			return OS_FAIL;
		}
		TimerInit(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.keyMgmtHskHsm.keyTimer);
		TimerInit(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.mgtAssoc.timer);
		TimerInit(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.mgtAuthReq.timer);
		TimerInit(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.mgtAuthRsp.timer);
#ifdef CONFIG_IEEE80211W
		TimerInit(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.SA_Query_Timer);
#endif
		TimerInit(&vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.btmreq_disassocTimer);
		ListPutItem(&vmacSta_p->StaCtl->FreeStaList, (ListItem *) (vmacSta_p->StaCtl->ExtStaInfoDb + i));

		/*Init MU db list */
		vmacSta_p->StaCtl->MUStaDb[i].nxt = NULL;
		vmacSta_p->StaCtl->MUStaDb[i].prv = NULL;
		vmacSta_p->StaCtl->MUStaDb[i].StaInfo_p = NULL;
		ListPutItem(&vmacSta_p->StaCtl->FreeMUStaList, (ListItem *) (vmacSta_p->StaCtl->MUStaDb + i));
	}

	vmacSta_p->StaCtl->Initialized = TRUE;
	SPIN_LOCK_INIT(&vmacSta_p->StaCtl->dbLock);
	return (OS_SUCCESS);
}

/*!
* Free Station database memory. 
* @param ExtStaInfoDb Pointer to a station database
* @return void         
*/

extern void extStaDb_Cleanup(vmacApInfo_t * vmacSta_p)
{
	if (vmacSta_p->EthStaCtl) {
		if (vmacSta_p->EthStaCtl->EthStaDb) {
			wl_kfree(vmacSta_p->EthStaCtl->EthStaDb);
		}
		wl_kfree(vmacSta_p->EthStaCtl);
	}

	if (vmacSta_p->master || !vmacSta_p->StaCtl)
		return;
	if (vmacSta_p->StaCtl->ExtStaInfoDb) {
		int i;
		for (i = 0; i < sta_num; i++) {
			if (vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.pn)
				wl_kfree(vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.pn);
		}
		wl_kfree(vmacSta_p->StaCtl->ExtStaInfoDb);
	}
	if (vmacSta_p->StaCtl->MUStaDb) {
		wl_kfree(vmacSta_p->StaCtl->MUStaDb);
	}
	wl_kfree(vmacSta_p->StaCtl);
}

/******************************************************************************
*
* Name: extStaDb_AddSta
*
* Description:
*    This routine adds a station or AP to the external station table.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): StaInfo - Pointer to a structure containing information
*                          about the station being added
*
* Return Value:
*    Status indicating the results of the operation; possbile values are:
*
*       NOT_INITIALIZED
*       STATION_EXISTS_ERROR
*       TABLE_FULL_ERROR
*       ADD_SUCCESS
*
* Notes:
*    None.
*
* PDL:
*    If the database has not been initialized Then
*       Return an uninitialized status
*    End If
*
*    Get the semaphore for access to the database
*    Call LocateAddr to get a pointer to the place in the table to add
*       the new station
*    If a station with the given MAC address is already in the table Then
*       Return the semaphore
*       Return a status indicating the station already exists
*    End If
*
*    If the list of available structures is not empty Then
*       Remove an available structure from the free list, fill it out with
*          the information for the new station and add it to the location
*          based on the pointer given by the LocateAddr call
*       Return the semaphore
*       Return success status
*    Else
*       Return a storage error
*    End If
* END PDL
*
*****************************************************************************/

/*!
* Add a station to the station database 
* @param StaInfo_p Pointer to a station info structure
* @return NOT_INITIALIZED,      
*         STATION_EXISTS_ERROR, 
*         TABLE_FULL_ERROR,     
*         ADD_SUCCESS          
*/
extern extStaDb_Status_e extStaDb_AddSta(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * StaInfo_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	ListItem *tmp;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;
	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find a spot where the station that is to be added  */
	/* can be placed; if the station is already in the table, give back */
	/* the semaphore and return status.                                 */
	/*------------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, &(StaInfo_p->Addr), &item_p, &idx)) != LOCATE_FAILURE) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (STATION_EXISTS_ERROR);
	}

	/*---------------------------------------------------------------*/
	/* Get a structure off of the free list, fill it out with the    */
	/* information about the new station, and put it in the location */
	/* found above.                                                  */
	/*---------------------------------------------------------------*/

	tmp = ListGetItem(&vmacSta_p->StaCtl->FreeStaList);
	if (tmp) {
		rx_pn_info_t *tmpPn;
		ExtStaInfoItem_t *search_p = vmacSta_p->StaCtl->ExtStaInfoDb_p[idx];
		item_p = (ExtStaInfoItem_t *) tmp;
		tmpPn = item_p->StaInfo.pn;	//store the memory pointer first
		memset(&item_p->StaInfo, 0, sizeof(extStaDb_StaInfo_t));
		item_p->StaInfo.pn = tmpPn;	//Resume the space 
		memset(item_p->StaInfo.pn, 0, sizeof(rx_pn_info_t));
		memcpy(&item_p->StaInfo.Addr, &StaInfo_p->Addr, sizeof(IEEEtypes_MacAddr_t));
		memcpy(&item_p->StaInfo.Bssid, &StaInfo_p->Bssid, sizeof(IEEEtypes_MacAddr_t));

		item_p->StaInfo.State = StaInfo_p->State;
		item_p->StaInfo.PwrMode = StaInfo_p->PwrMode;
		item_p->StaInfo.StnId = StaInfo_p->StnId;
		item_p->StaInfo.Aid = StaInfo_p->Aid;
		item_p->StaInfo.ApMode = StaInfo_p->ApMode;
		item_p->StaInfo.ClientMode = StaInfo_p->ClientMode;
#ifdef WDS_FEATURE
		item_p->StaInfo.AP = StaInfo_p->AP;
		item_p->StaInfo.wdsInfo = StaInfo_p->wdsInfo;
		item_p->StaInfo.wdsPortInfo = StaInfo_p->wdsPortInfo;
#else
#ifdef MBSS
		item_p->StaInfo.AP = StaInfo_p->AP;
#endif
#endif
#ifdef CLIENT_SUPPORT
		item_p->StaInfo.Client = StaInfo_p->Client;
#endif
		item_p->StaInfo.IsStaMSTA = 0;
		item_p->StaInfo.StaType = 0;
		memset(&item_p->StaInfo.aggr11n, 0, sizeof(Aggr11n));
		item_p->StaInfo.aggr11n.ampducfg = 0xFF;
		item_p->StaInfo.aggr11n.amsducfg.priority_aggr = 0xff;
		memset(&item_p->StaInfo.HtElem, 0, sizeof(IEEEtypes_HT_Element_t));
		memset(&item_p->StaInfo.AddHtElme, 0, sizeof(IEEEtypes_Add_HT_Element_t));

		item_p->StaInfo.MUStaListNode = NULL;
		item_p->StaInfo.MUset = NULL;
#ifdef MRVL_80211R
		memset(&item_p->StaInfo.keyMgmtStateInfo.RsnIEBuf, 0, MAX_SIZE_RSN_IE_BUF);
		memset(&item_p->StaInfo.keyMgmtStateInfo.mdie_buf, 0, MAX_SIZE_MDIE_BUF);
		memset(&item_p->StaInfo.keyMgmtStateInfo.ftie_buf, 0, MAX_SIZE_FTIE_BUF);
		item_p->StaInfo.keyMgmtStateInfo.pending_assoc = 0;
		item_p->StaInfo.keyMgmtStateInfo.reassoc = 0;
		item_p->StaInfo.keyMgmtStateInfo.assoc = NULL;
#endif
		SPIN_LOCK_INIT(&item_p->StaInfo.aggr11n.Lock);
		skb_queue_head_init(&item_p->StaInfo.aggr11n.txQ);
		memset(&item_p->StaInfo.DeFragBufInfo, 0, sizeof(DeFragBufInfo_t));
		item_p->StaInfo.DeFragBufInfo.FragNo = 255;	//default value 
		item_p->StaInfo.mib_p = StaInfo_p->mib_p;
		item_p->StaInfo.dev = StaInfo_p->dev;
		item_p->StaInfo.addba_rxamsdu = TRUE;
#ifdef CONFIG_IEEE80211W
		TimerDisarm(&item_p->StaInfo.SA_Query_Timer);
#endif
		TimerDisarm(&item_p->StaInfo.btmreq_disassocTimer);
		if (search_p) {	/*if hash table index idx already exist */
			while (search_p->nxt_ht) {
				search_p = search_p->nxt_ht;
			}
			search_p->nxt_ht = item_p;
			item_p->prv_ht = search_p;
			item_p->nxt_ht = NULL;
		} else {	/*put item to hash table idx */
			item_p->nxt_ht = item_p->prv_ht = NULL;
			vmacSta_p->StaCtl->ExtStaInfoDb_p[idx] = item_p;
		}

		ListPutItem(&vmacSta_p->StaCtl->StaList, tmp);
		item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes;

		/*-------------------------------------------------------*/
		/* Finished - give back the semaphore and return status. */
		/*-------------------------------------------------------*/
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		ap8xLnxStat_clients_WQadd(vmac_p, &StaInfo_p->Addr, 0);
		return (ADD_SUCCESS);
	} else {
		/*-------------------------------------------------------------*/
		/* There is no room in the table to add the station; give back */
		/* the semaphore and return status.                            */
		/*-------------------------------------------------------------*/
		/* Remove the least active station, and use the space for the new
		 * one */
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (TABLE_FULL_ERROR);
	}
}

/*!
* station aging timer tick process, will age out out station when age timer expired 
* @param data Pointer to user defined data
*/

void extStaDb_ProcessKeepAliveTimer(UINT8 * data)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;
	if (!vmacSta_p->download) {
		//wlFwSetKeepAliveTick(vmacSta_p->dev,0);
	}

	TimerRearm(&vmacSta_p->KeepAliveTimer, AGING_TIMER_VALUE_IN_SECONDS);
}

void Disable_extStaDb_ProcessKeepAliveTimer(vmacApInfo_t * vmacSta_p)
{
	TimerRemove(&vmacSta_p->KeepAliveTimer);
}

extern void extStaDb_ProcessKeepAliveTimerInit(vmacApInfo_t * vmacSta_p)
{
	TimerInit(&vmacSta_p->KeepAliveTimer);
	TimerFireIn(&vmacSta_p->KeepAliveTimer, 1, &extStaDb_ProcessKeepAliveTimer, (unsigned char *)vmacSta_p, AGING_TIMER_VALUE_IN_SECONDS);
}

void stationAging(UINT8 * data)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;
	extStaDb_ProcessAgeTick(data);
	ethStaDb_ProcessAgeTick(data);
	TimerRearm(&vmacSta_p->AgingTimer, AGING_TIMER_VALUE_IN_SECONDS * 10);
}

void Disable_stationAgingTimer(vmacApInfo_t * vmacSta_p)
{
	TimerRemove(&vmacSta_p->AgingTimer);
}

extern void extStaDb_AgingTimerInit(vmacApInfo_t * vmacSta_p)
{
	/** Start aging timer */
	TimerInit(&vmacSta_p->AgingTimer);
	TimerFireIn(&vmacSta_p->AgingTimer, 1, &stationAging, (unsigned char *)vmacSta_p, AGING_TIMER_VALUE_IN_SECONDS * 10);
}

#ifdef MBSS
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p, UINT8 * macAddr_p);
#endif
#ifdef SOC_W906X
extern int StaKeepAliveCheck(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * StaInfo_p, int cmd);
#define STA_KEEP_ALIVE_CHECK_THRES	6	// 6 x 10sec
#endif				/* SOC_W906X */
void extStaDb_ProcessAgeTick(UINT8 * data)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;
#ifdef SOC_W906X
#ifdef MBSS
	vmacApInfo_t *vmactem_p = NULL;
#endif
#endif
	ExtStaInfoItem_t *Curr_p, *Item_p;
	extStaDb_StaInfo_t *StaInfo_p;
	UINT32 count = 0;
	unsigned long dbflags;

	/* Traverse the aging list,
	 *  Remove the aged ones, and send proper Disassociate message or
	 * Deauthenticate message
	 */
	WLDBG_INFO(DBG_LEVEL_10, "extStaDb_ProcessAgeTick \n");
	if (!vmacSta_p->StaCtl->Initialized) {
		return;
	}

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	while (Curr_p != NULL) {
		if (count++ > EXT_STA_TABLE_SIZE)
			break;
		Item_p = Curr_p;
#ifdef SC_PALLADIUM		/* Disable ageing for Palladium */
		if (1)		//--Item_p->StaInfo.TimeStamp)
#else
		if ((Item_p->StaInfo.StaType & 0x02) == 0x02) {
			Curr_p = Curr_p->nxt;
			continue;
		}
		if (--Item_p->StaInfo.TimeStamp)
#endif
		{
			Curr_p = Curr_p->nxt;
#ifdef SOC_W906X
#ifdef CLIENT_SUPPORT
			if (!Item_p->StaInfo.AP && !Item_p->StaInfo.Client)
#else
			if (!Item_p->StaInfo.AP)
#endif
			{

				if (Item_p->StaInfo.TimeStamp == vmacSta_p->StaCtl->aging_time_in_minutes - 1) {
					StaKeepAliveCheck(vmacSta_p, &Item_p->StaInfo, 0);	//reset tx succ cnt
				} else if (Item_p->StaInfo.TimeStamp <= STA_KEEP_ALIVE_CHECK_THRES) {
					int ts = Item_p->StaInfo.TimeStamp;
					SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
					StaKeepAliveCheck(vmacSta_p, &Item_p->StaInfo, 1);	//send tx test pkt
					SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
					Item_p->StaInfo.TimeStamp = ts;
				}
			}
#endif				/* SOC_W906X */
		} else {
			/* Item can be aged, This involves removing the item
			 * from the list and also, send message to the station
			 */
			if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, &(Item_p->StaInfo.Addr), STADB_NO_BLOCK | STADB_SKIP_MATCH_VAP)) == NULL) {
				/* Station not known, do nothing */
				SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
				return;
			}
#ifdef CLIENT_SUPPORT
			if (StaInfo_p->AP || StaInfo_p->Client)
#else
			if (StaInfo_p->AP)
#endif
			{
				{
					Curr_p = Curr_p->nxt;
					continue;
				}
			} else {
#ifdef SOC_W906X
				int sta_alive;
				SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
				sta_alive = StaKeepAliveCheck(vmacSta_p, StaInfo_p, 2);	// check tx succ cnt
				SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

				if (sta_alive) {
					Item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes;
					Curr_p = Curr_p->nxt;
					continue;
				}
#endif				/* SOC_W906X */
#ifdef AP_URPTR
				/* Clean up UR hash table for this STA */
				urHash_RemoveSta(vmacSta_p, &(Item_p->StaInfo.Addr), 0);
#endif
				if (StaInfo_p->State == ASSOCIATED) {
					SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
					cleanupAmpduTx(vmacSta_p, (UINT8 *) & Item_p->StaInfo.Addr);
#ifdef SOC_W906X
#ifdef MBSS
					if ((vmactem_p = vmacGetMBssByAddr(vmacSta_p, StaInfo_p->Bssid)) != NULL)
						// Find the correct virtual interface to send Deauth packet
						macMgmtMlme_SendDeauthenticateMsg(vmactem_p, &Item_p->StaInfo.Addr, Item_p->StaInfo.StnId,
										  IEEEtypes_REASON_DISASSOC_INACTIVE, FALSE);
					else
#endif
						macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &Item_p->StaInfo.Addr, Item_p->StaInfo.StnId,
										  IEEEtypes_REASON_DISASSOC_INACTIVE, FALSE);
#else
					macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &Item_p->StaInfo.Addr, Item_p->StaInfo.StnId,
									  IEEEtypes_REASON_DISASSOC_INACTIVE);
#endif
					SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
					FreeAid(vmacSta_p, StaInfo_p->Aid);
					ResetAid(vmacSta_p, StaInfo_p->StnId, StaInfo_p->Aid);
					StaInfo_p->Aid = 0;

				}
				if (StaInfo_p->PwrMode == PWR_MODE_PWR_SAVE) {
					if (vmacSta_p->PwrSaveStnCnt)
						vmacSta_p->PwrSaveStnCnt--;
					StaInfo_p->PwrMode = PWR_MODE_ACTIVE;
				}
				if (StaInfo_p->ClientMode == BONLY_MODE)
					macMgmtMlme_DecrBonlyStnCnt(vmacSta_p, 0);

				if (!StaInfo_p->CapInfo.ShortPreamble)
					macMgmtMlme_DecrBarkerPreambleStnCnt(vmacSta_p);

			}
			if (StaInfo_p->Aid != 0) {
				FreeAid(vmacSta_p, StaInfo_p->Aid);
				ResetAid(vmacSta_p, StaInfo_p->StnId, StaInfo_p->Aid);
				StaInfo_p->Aid = 0;
			}
			StaInfo_p->State = UNAUTHENTICATED;
			StaInfo_p->mu_sta = 0;

			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#ifdef APEVT_STA_ASSOC_SUPPORT

			apEvtRun(APEVT_STA_ASSOC, (uint8 *) & StaInfo.Addr, APEVT_STA_DEAUTHENTICATED);
#endif
			extStaDb_DelSta(vmacSta_p, &(Item_p->StaInfo.Addr), STADB_DONT_UPDATE_AGINGTIME);
#ifdef STADB_IN_CACHE
			{
				// Delete aging timeout station at all virtual interface STADB_IN_CACHE
				UINT8 i;
				struct wlprivate *wlpptr, *wlpptr1;
				wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
				for (i = 0; wlpptr->vdev[i] && i <= bss_num; i++) {
					wlpptr1 = NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]);
					extStaDb_DelCachedStaInfo(wlpptr1->vmacSta_p, &(Item_p->StaInfo.Addr));
				}
			}
#endif
			FreeStnId(vmacSta_p, StaInfo_p->StnId);
			wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & (Item_p->StaInfo.Addr), 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);

			/* need not update the current as, this is already done
			 * as a result of previous two item_p updates */
			WLDBG_EXIT(DBG_LEVEL_10);

			return;
		}
		/*Curr_p = Curr_p->nxt; */
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

void extStaDb_RemoveAllStns(vmacApInfo_t * vmac_p, UINT16 Reason)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
	ExtStaInfoItem_t *Curr_p, *Item_p;
	extStaDb_StaInfo_t *StaInfo_p;
	vmacApInfo_t *vmacSta_p;
	int removeall = 0;
	unsigned long dbflags;
	int deauth_cnt = 0;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else {
		vmacSta_p = vmac_p;
		//this is not from vitual interface, need to remove all.
		removeall = 1;
	}
	if (!vmacSta_p->StaCtl->Initialized) {
		return;
	}
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	/* Traverse the aging list,
	 * Remove the aged ones, and send proper Disassociate message or
	 * Deauthenticate message
	 */
	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		{
			/* Item can be aged, This involves removing the item
			 * from the list and also, send message to the station
			 * Only remove station in the BSS
			 */
			if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr), STADB_NO_BLOCK)) == NULL
			    || memcmp(&vmac_p->macBssId, &StaInfo_p->Bssid, sizeof(IEEEtypes_MacAddr_t))) {
				//if call from wdev, remove it too.
				if (removeall) {
					SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
					extStaDb_DelSta(vmac_p, &(Item_p->StaInfo.Addr), STADB_DONT_UPDATE_AGINGTIME);
					SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
					Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
					continue;
				}
				/* Station not known, do nothing */
				Curr_p = Curr_p->nxt;
				//break;
				continue;
			}
			if (StaInfo_p->State == ASSOCIATED) {
				SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#ifdef SOC_W906X
				macMgmtMlme_SendDeauthenticateMsg(vmac_p, &Item_p->StaInfo.Addr, Item_p->StaInfo.StnId, Reason, FALSE);
#else
				macMgmtMlme_SendDeauthenticateMsg(vmac_p, &Item_p->StaInfo.Addr, Item_p->StaInfo.StnId, Reason);
#endif
				/* remove the Mac address from the ethernet MAC address table */
				macMgmtCleanUp(vmac_p, StaInfo_p);
				deauth_cnt = 1;
				SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
			}
			Curr_p = Curr_p->nxt;
		}
	}

	/* add delay for vap0 ~ vap7 only */
	if (deauth_cnt && (wlpptr->vap_id < 8)) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		mdelay(500);
		SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	}
	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);

	while (Curr_p != NULL) {
		Item_p = Curr_p;
		{
			if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr), STADB_NO_BLOCK)) == NULL
			    || memcmp(&vmac_p->macBssId, &StaInfo_p->Bssid, sizeof(IEEEtypes_MacAddr_t))) {
				/* Station not known, do nothing. If multiple BSSs are active, the STA found may not belong to  the current VAP */
				Curr_p = Curr_p->nxt;
				/*break; */
				continue;
			}

			if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr), STADB_NO_BLOCK)) != NULL) {
				SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
				if (StaInfo_p->Aid) {
					FreeAid(vmacSta_p, StaInfo_p->Aid);
					StaInfo_p->Aid = 0;
				}
				StaInfo_p->State = UNAUTHENTICATED;
				FreeStnId(vmac_p, StaInfo_p->StnId);
				extStaDb_DelSta(vmac_p, &(Item_p->StaInfo.Addr), STADB_DONT_UPDATE_AGINGTIME);
				wlFwSetNewStn(vmac_p->dev, (u_int8_t *) & (Item_p->StaInfo.Addr), 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
				SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
			}
		}
		Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

/******************************************************************************
*
* Name: extStaDb_DelSta
*
* Description:
*    This routine deletes a station from the external station table.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p  - Pointer to the MAC address of the station to be
*                          deleted
*
* Return Value:
*    Status indicating the results of the operation; possbile values are:
*
*       NOT_INITIALIZED
*       LOCATE_FAILURE
*       DEL_SUCCESS
*
* Notes:
*    None.
*
* PDL:
*    If the database has not been initialized Then
*       Return an uninitialized status
*    End If
*
*    Get the semaphore for access to the database
*    Call LocateAddr to get a pointer to the structure in the table
*       corresponding to the given station that is to be removed
*    If a station could not be located in the table Then
*       Return the semaphore
*       Return status indicating failure to locate the station
*    End If
*
*    Remove that found structure from the table and put it back on the
*       free list
*    Return the semaphore
*    Return success status
* END PDL
*
*****************************************************************************/
/*!
* Remove a station from the station database 
* @param Addr_p Pointer to a station mac address
* @return NOT_INITIALIZED,      
*         LOCATE_FAILURE, 
*         DEL_SUCCESS     
*/
extern extStaDb_Status_e extStaDb_DelSta(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, int option)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;
	unsigned long dbflags = 0;
	muset_t *muset_p;
	bool need_lock = !(option & STADB_NO_BLOCK);
	u32 tid = 0;
#ifdef SOC_W8964
	unsigned long MUlistflags, MUSetflags, txRateHistoflags;
#endif
	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	mib = vmacSta_p->Mib802dot11;

#ifdef AP_URPTR
	urHash_RemoveSta(vmacSta_p, Addr_p, 1);
#endif
	ap8xLnxStat_clients_WQadd(vmac_p, Addr_p, 1);

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	if (need_lock)
		SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be deleted; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx);

	if ((result != LOCATE_SUCCESS) || !item_p) {
		if (need_lock)
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}
#ifdef STADB_IN_CACHE
	/*-----------------------------------------------------------------*/
	/* Del the cached stadb info if deleted station is found           */
	/* Always delete!                                                  */
	/*-----------------------------------------------------------------*/
	extStaDb_DelCachedStaInfo(vmac_p, Addr_p);
#endif				/* STADB_IN_CACHE */

	/*Everytime delete client, remove entry in multicast proxy list too */
	if (*(mib->mib_MCastPrxy))
		McastProxyUCastAddrRemove(vmacSta_p, Addr_p);

#ifdef SOC_W8964
	/* To avoid SMP deadlocks be sure the locking order is:
	 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */
	SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
#endif
	/*When remove station from associated sta hash table, clean up MUStaList and then MUset. 
	 * ALWAYS call these two functions together when station disassoc
	 */
	muset_p = item_p->StaInfo.MUset;	//save a local copy before StaInfo.MUset is reset in MURemStaFromMUSet
	MUDelStaFromMUStaList(vmac_p, item_p->StaInfo.MUStaListNode);
#ifdef SOC_W8964
	MUDel_MUSet(vmac_p, muset_p, MUSet_FW_DEL | MUSet_NO_GID_FRAME);

	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
	SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock, MUlistflags);

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->txRateHistoLock[item_p->StaInfo.StnId - 1], txRateHistoflags);

	if (wlpptr->wlpd_p->txRateHistogram[item_p->StaInfo.StnId - 1] != NULL) {
		wl_kfree(wlpptr->wlpd_p->txRateHistogram[item_p->StaInfo.StnId - 1]);
		wlpptr->wlpd_p->txRateHistogram[item_p->StaInfo.StnId - 1] = NULL;
	}

	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->txRateHistoLock[item_p->StaInfo.StnId - 1], txRateHistoflags);
#else
	MUDel_MUSet(vmac_p, muset_p, MUSet_BLOCK);
	if (wlpptr->wlpd_p->txRateHistogram[item_p->StaInfo.StnId] != NULL) {
		memset(wlpptr->wlpd_p->txRateHistogram[item_p->StaInfo.StnId], 0, sizeof(WLAN_TX_RATE_HIST));
	}

	if ((item_p->StaInfo.StnId < sta_num) && (wlpptr->wlpd_p->scheHistogram[item_p->StaInfo.StnId] != NULL)) {
		memset(wlpptr->wlpd_p->scheHistogram[item_p->StaInfo.StnId], 0, sizeof(WLAN_SCHEDULER_HIST));
	}

	if (item_p->StaInfo.pDefragSkBuff) {
		struct except_cnt *wlexcept_p = &wlpptr->wlpd_p->except_cnt;

		wl_free_skb(item_p->StaInfo.pDefragSkBuff);
		item_p->StaInfo.pDefragSkBuff = NULL;
		wlexcept_p->cnt_defrag_drop++;
		wlexcept_p->cnt_defrag_drop_x[7]++;
	}
#endif

	/*----------------------------------------*/
	/* Put the element back on the free list. */
	/*----------------------------------------*/
	{
		ExtStaInfoItem_t *search_p = vmacSta_p->StaCtl->ExtStaInfoDb_p[idx];
		if (search_p) {

			while (memcmp(&(search_p->StaInfo.Addr), item_p->StaInfo.Addr, 6 * sizeof(IEEEtypes_Addr_t))) {

				search_p = search_p->nxt_ht;
			}

		}
		if (search_p && item_p) {
			if (search_p->prv_ht && search_p->nxt_ht) {	/*middle element */

				item_p->nxt_ht->prv_ht = item_p->prv_ht;
				item_p->prv_ht->nxt_ht = item_p->nxt_ht;
			} else {
				if (search_p->prv_ht) {	/*this is tail */
					search_p->prv_ht->nxt_ht = NULL;
				} else if (search_p->nxt_ht) {	/*this is header */
					search_p->nxt_ht->prv_ht = NULL;
					vmacSta_p->StaCtl->ExtStaInfoDb_p[idx] = search_p->nxt_ht;
				} else {	/*one and only */
					vmacSta_p->StaCtl->ExtStaInfoDb_p[idx] = NULL;
				}
			}

			item_p->nxt_ht = item_p->prv_ht = NULL;
		}

	}

#ifdef CONFIG_IEEE80211W
	if (item_p->StaInfo.Ieee80211wSta == 0)
		vmacSta_p->Non80211wStaCnt--;
#endif

	TimerRemove(&item_p->StaInfo.mgtAssoc.timer);
	TimerRemove(&item_p->StaInfo.mgtAuthReq.timer);
	TimerRemove(&item_p->StaInfo.mgtAuthRsp.timer);
	TimerRemove(&item_p->StaInfo.keyMgmtHskHsm.timer);
	TimerRemove(&item_p->StaInfo.keyMgmtHskHsm.keyTimer);
	skb_queue_purge(&item_p->StaInfo.aggr11n.txQ);
#ifdef MRVL_80211R
	if (item_p->StaInfo.keyMgmtStateInfo.pending_assoc) {
		if (item_p->StaInfo.keyMgmtStateInfo.assoc) {
			wl_free_skb(item_p->StaInfo.keyMgmtStateInfo.assoc);
			item_p->StaInfo.keyMgmtStateInfo.assoc = NULL;
		}
		item_p->StaInfo.keyMgmtStateInfo.pending_assoc = 0;
		item_p->StaInfo.keyMgmtStateInfo.reassoc = 0;
	}
#endif
#ifdef SOC_W906X
	if (wlpptr->wlpd_p->bfwreset == TRUE) {
		FreeStnId_newdp(vmacSta_p, item_p->StaInfo.StnId);
	}

	if (item_p->StaInfo.StnId < sta_num)
		for (tid = 0; tid < MAX_UP; tid++)
			TimerRemove(&wlpptr->wlpd_p->AmpduPckReorder[item_p->StaInfo.StnId].timer[tid]);
#endif				//SOC_W906X
	item_p->StaInfo.aggr11n.ampducfg = 0xFF;
	item_p->StaInfo.aggr11n.amsducfg.priority_aggr = 0xFF;
	TimerDisarm(&item_p->StaInfo.btmreq_disassocTimer);
	ListPutItem(&vmacSta_p->StaCtl->FreeStaList, ListRmvItem(&vmacSta_p->StaCtl->StaList, (ListItem *) item_p));
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	if (need_lock)
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	ethStaDb_RemoveStaPerWlan(vmacSta_p, Addr_p);
#ifdef NPROTECTION
	extStaDb_entries(vmac_p, 0);
	HandleNProtectionMode(vmac_p);
#endif


	return (DEL_SUCCESS);
}

/******************************************************************************
*
* Name: extStaDb_GetStnInfo
*
* Description:
*    This routine attempts to retrieve the state for the given MAC address.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p  - Pointer to the MAC address of the station for
*                          which the state is to be retrieved
*    Arg2 (  o): State_p - Pointer to the variable that will contain the
*                          requested station information
*
* Return Value:
*    Status indicating the results of the operation; possbile values are:
*
*       NOT_INITIALIZED
*       LOCATE_FAILURE
*       STATE_SUCCESS
*
* Notes:
*    None.
*
* PDL:
*    If the database has not been initialized Then
*       Return an uninitialized status
*    End If
*
*    Get the semaphore for access to the database
*    Call LocateAddr to get a pointer to the structure in the table
*       corresponding to the given station
*    If a station could not be located in the table Then
*       Return the semaphore
*       Return status indicating failure to locate the station
*    End If
*
*    Retrieve the station info for the given station
*
*    Return the semaphore
*    Return status indicating results of the operation
* END PDL
*
*****************************************************************************/
/*!
* Check to see if station exist in the station database 
* @param Addr_p Pointer to a station mac address
* @param resetAgeTime Flag to indicate reset the aging time
* @return Pointer to the station info struct,      
*         NULL 
*/
extern extStaDb_StaInfo_t *extStaDb_GetStaInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, int option)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags = 0;
	bool need_lock = !(option & STADB_NO_BLOCK);

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return NULL;
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	if (need_lock)
		SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

#ifdef STADB_IN_CACHE
	if ((option & STADB_FIND_IN_CACHE) && (StaInfo_p = extStaDb_GetCachedStaInfo(vmac_p, Addr_p))) {
		if (need_lock)
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

		return StaInfo_p;
	}
#endif				/* STADB_IN_CACHE */

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/* if not found, give back the semaphore and return error status.   */
	/*------------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		if (need_lock)
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return NULL;
	}

	/*-------------------------------------------*/
	/* Fill out the requested state information. */
	/*-------------------------------------------*/
	StaInfo_p = &item_p->StaInfo;

	if ((option != STADB_DONT_UPDATE_AGINGTIME) && ((StaInfo_p->State == ASSOCIATED)
#ifdef WDS_FEATURE
							|| StaInfo_p->AP
#endif				//WDS_FEATURE
	    )) {
		item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes;	/* AGING_TIME; */
	}
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	if (need_lock)
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	if (StaInfo_p->Client)
		goto stadb_found;
	else {
		//for AP filter out station not from same BSSID
		//option STADB_SKIP_MATCH_VAP is to check other VAP's station
		if (option & STADB_SKIP_MATCH_VAP) {
			goto stadb_found;
		}
		if (!memcmp(&vmac_p->macBssId, &StaInfo_p->Bssid, sizeof(IEEEtypes_MacAddr_t)))
			goto stadb_found;
		else
			return NULL;
	}
 stadb_found:
#ifdef STADB_IN_CACHE
	/* inf the update flag is set */
	if (option & STADB_UPDATE_CACHE)
		extStaDb_UpdateCachedStaInfo(vmac_p, StaInfo_p);
#endif
	return StaInfo_p;
}

/*============================================================================= */
/*                         CODED PRIVATE PROCEDURES */
/*============================================================================= */

/******************************************************************************
*
* Name: Jenkins32BitMix
*
* Description:
*   Routine that performs a hash on a 32 bit number.
*
* Conditions For Use:
*   None.
*
* Arguments:
*    Arg1 (i  ): Key - 32 bit value that will be hashed
*
* Return Value:
*   The index produced from hashing
*
* Notes:
*   This is just experimental at this time.
*
* PDL:
*    Implement the Jenkins 32 bit mix hash function
* END PDL
*
*****************************************************************************/
inline static UINT32 Jenkins32BitMix(UINT32 Key)
{
	Key += (Key << 12);
	Key ^= (Key >> 22);
	Key += (Key << 4);
	Key ^= (Key >> 9);
	Key += (Key << 10);
	Key ^= (Key >> 2);
	Key += (Key << 7);
	Key ^= (Key >> 12);

	return (Key);
}

/******************************************************************************
*
* Name: Wang32BitMix
*
* Description:
*   Routine that performs a hash on a 32 bit number.
*
* Conditions For Use:
*   None.
*
* Arguments:
*    Arg1 (i  ): Key - 32 bit value that will be hashed
*
* Return Value:
*   The index produced from hashing
*
* Notes:
*   This is just experimental at this time.
*
* PDL:
*    Implement the Wang 32 bit mix hash function
* END PDL
*
*****************************************************************************/
UINT32 Wang32BitMix(UINT32 Key)
{
	Key += ~(Key << 15);
	Key ^= (Key >> 10);
	Key += (Key << 3);
	Key ^= (Key >> 6);
	Key += ~(Key << 11);
	Key ^= (Key >> 16);

	return (Key);
}

UINT32(*Wang32BitMixFp) (UINT32 Key) = Wang32BitMix;

/******************************************************************************
*
* Name: Hash
*
* Description:
*   Routine that takes a key, performs a hash on that key, and then
*   scales the resulting index down to the size of the hash table. In this
*   case, the hash table is the table of external stations.
*
* Conditions For Use:
*   None.
*
* Arguments:
*    Arg1 (i  ): Key - 32 bit value that will be hashed
*
* Return Value:
*   The index produced from hashing and scaling
*
* Notes:
*   The values returned by the hashing functions are 32 bit unsigned
*   values. Hence, to get an index for the hash table, the result from
*   the hash must be normalized by the largest 32 bit number and then
*   multiplied by the table size to yield an index appropriate for the
*   hash table.
*
* PDL:
*    Call a routine to do the hash
*    Scale and return the result
* END PDL
*
*****************************************************************************/
inline static UINT32 Hash(UINT32 Key)
{
	unsigned int result;

	/*-------------------------------------------------------------*/
	/* Call a hash function; the current routines are experimental */
	/* and not final.                                              */
	/*-------------------------------------------------------------*/
	/* result = Jenkins32BitMix(Key); */
	result = (*Wang32BitMixFp) (Key);
	//result = Wang32BitMix(Key); 

	/*------------------------------------------------------------------*/
	/* Scale the result of the hash down to the size of the hash table. */
	/*------------------------------------------------------------------*/

	/*Try not to use floating point computations.... Rahul */

	//result = ((float)result / ULONG_MAX) * EXT_STA_TABLE_SIZE_RUNNING;
	result = result % EXT_STA_TABLE_SIZE_RUNNING;
	return (result);
}

/******************************************************************************
*
* Name: LocateAddr
*
* Description:
*    This routine attempts to locate a given MAC address in the external
*    station table. If the MAC address is not currently stored in the table,
*    the pointer returned indicates where it can be added.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p - Pointer to the MAC address of the station to be
*                         located
*    Arg2 (  o): Item_p - Pointer to the structure in the external station
*                         table if a station with the supplied MAC address
*                         has been found; otherwise, it points to a location
*                         in the table where a station with the given MAC
*                         address can be added
*
* Return Value:
*    Status indicating the results of the operation; possbile values are:
*
*       LOCATE_FAILURE
*       LOCATE_SUCCESS
*
* Notes:
*    If the routine fails to locate a station with the given MAC address in
*    the table, the pointer returned can be used to indicate where to insert
*    the new station; if the pointer is NULL, it means there are no stations
*    in the location resulting from hashing on the MAC address, so the
*    station can be placed at that location. If the pointer is not NULL,
*    then other stations have been placed at the same location (a collision
*    has occurred). In this case the station can be added to a list built
*    up for stations mapped to that location - specifically, the station can
*    be placed on the list by adding it after the structure pointed to by the
*    pointer that is returned.
*
* PDL:
*    Extract the lower 32 bits of the MAC address to be used for hashing
*    Call Hash to get an index into the external station table
*    Search through the list (if one exists) for the given MAC address
*    If found Then
*       Return a pointer to the structure and return success status as well
*    Else
*       Return a pointer to where the station can be added and return
*          failure status as well
*    End If
* END PDL
*
*****************************************************************************/
static extStaDb_Status_e LocateAddr(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, ExtStaInfoItem_t ** Item_pp, UINT32 * Idx_p)
{
	UINT32 key;
	vmacApInfo_t *vmacSta_p;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	/*---------------------------------------------------------------------*/
	/* First, get the lower 32 bits of the MAC address to use for hashing. */
	/*---------------------------------------------------------------------*/
	memcpy(&key, ((IEEEtypes_Addr_t *) Addr_p + 2 * sizeof(IEEEtypes_Addr_t)), 4 * sizeof(IEEEtypes_Addr_t));
	/*
	   if (!((UINT32)Addr_p & 0x3))//Check if Addr_p is at a 4 byte boundary
	   {//Addr_p is at 4 byte boundary.
	   key = (*Addr_p)[2] | ((*Addr_p)[3] << 8) | ((*Addr_p)[4] << 16) | ((*Addr_p)[5] << 24);
	   }
	   else
	   {//Addr_p+2 is at 4 byte boundary
	   key = *((UINT32 *)((UINT8 *)Addr_p+2));
	   }
	 */
	/*-----------------------------------------------------------*/
	/* Next, hash to get an index into the table that stores MAC */
	/* addresses and associated information.                     */
	/*-----------------------------------------------------------*/
	*Idx_p = Hash(key);

	/*-------------------------------------------------*/
	/* Now see if the address is already in the table. */
	/*-------------------------------------------------*/
	*Item_pp = vmacSta_p->StaCtl->ExtStaInfoDb_p[*Idx_p];
	if (*Item_pp == NULL) {
		return (LOCATE_FAILURE);
	} else {
		if (!memcmp((*Item_pp)->StaInfo.Addr, Addr_p, 6 * sizeof(IEEEtypes_Addr_t))) {
			return (LOCATE_SUCCESS);
		} else {
			while ((*Item_pp)->nxt_ht != NULL) {
				*Item_pp = (*Item_pp)->nxt_ht;

				if (!memcmp((*Item_pp)->StaInfo.Addr, Addr_p, 6 * sizeof(IEEEtypes_Addr_t))) {
					return (LOCATE_SUCCESS);
				}
			}
		}
	}

	return (LOCATE_FAILURE);
}

/*!
* Stations in station database
* @param none
* @return number of stations      
*/
extern UINT16 extStaDb_entries(vmacApInfo_t * vmac_p, UINT8 flag)
{
	ListItem *search;
	ExtStaInfoItem_t *search1;
	UINT16 StaList_entries = 0;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#ifdef NPROTECTION
	CleanCounterClient(vmac_p);
#endif
	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
#ifdef APCFGUR
		if (flag == 1) {
			if (search1->StaInfo.UR && (search1->StaInfo.State == ASSOCIATED))
				StaList_entries++;
		} else
#endif
#ifdef PPPoE_SUPPORT
		if (flag == 2) {
			if (((search1->StaInfo.AP == FALSE) && ((search1->StaInfo.State == ASSOCIATED))) || search1->StaInfo.AP) {
				StaList_entries++;
			}
		} else
#endif
		if ((search1->StaInfo.AP == FALSE) && ((search1->StaInfo.State == AUTHENTICATED) || (search1->StaInfo.State == ASSOCIATED))) {
			if (!memcmp(&vmac_p->macBssId, &search1->StaInfo.Bssid, sizeof(IEEEtypes_MacAddr_t)))
				StaList_entries++;
#ifdef NPROTECTION
			ClientStatistics(vmac_p, &search1->StaInfo);
#endif
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (StaList_entries);

}

extern UINT16 extStaDb_entries2(vmacApInfo_t * vmac_p, UINT8 flag)
{
	ListItem *search;
	ExtStaInfoItem_t *search1;
	UINT16 StaList_entries = 0;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
		if (1 /**(search1->StaInfo.AP == FALSE) && ((search1->StaInfo.State == AUTHENTICATED) || (search1->StaInfo.State == ASSOCIATED))**/ ) {
			if (1 /**!memcmp(&vmac_p->macBssId, &search1->StaInfo.Bssid,sizeof(IEEEtypes_MacAddr_t))**/ )
				StaList_entries++;
#ifdef NPROTECTION
			ClientStatistics(vmac_p, &search1->StaInfo);
#endif
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (StaList_entries);

}

/*!
* list all stations' mac addresses to buf
* @param buf Pointer to station list data structure
* @return OS_SUCCESS
*         OS_FAIL      
*/
extern UINT16 extStaDb_list(vmacApInfo_t * vmac_p, UINT8 * buf, UINT8 get)
{
	int j;
	ListItem *search;
	ExtStaInfoItem_t *search1;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	j = 0;

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
#ifdef PPPoE_SUPPORT
		if (get == 3) {
			if ((search1->StaInfo.AP == FALSE && (search1->StaInfo.State == ASSOCIATED)) || search1->StaInfo.AP) {
				UINT32 *ptr;
				ptr = (UINT32 *) & buf[j];
				*ptr = (UINT32) & search1->StaInfo;
				j += 4;
			}
		} else
#endif
#ifdef APCFGUR
		if (get == 2) {
			if (search1->StaInfo.UR && (search1->StaInfo.State == ASSOCIATED)) {
				UINT32 *ptr;
				ptr = (UINT32 *) & buf[j];
				*ptr = (UINT32) & search1->StaInfo;
				j += 4;
			}
		} else
#endif
			if ((search1->StaInfo.AP == FALSE) && ((search1->StaInfo.State == AUTHENTICATED) ||	//removed for now JS
							       (search1->StaInfo.State == ASSOCIATED))
			    && (!memcmp(&vmac_p->macBssId, &search1->StaInfo.Bssid, sizeof(IEEEtypes_MacAddr_t)))) {
			/*station mac address */
			buf[j++] = search1->StaInfo.Addr[0];
			buf[j++] = search1->StaInfo.Addr[1];
			buf[j++] = search1->StaInfo.Addr[2];
			buf[j++] = search1->StaInfo.Addr[3];
			buf[j++] = search1->StaInfo.Addr[4];
			buf[j++] = search1->StaInfo.Addr[5];
#ifndef STA_INFO_DB
			buf[j++] = 0;
#endif
			/*station association state */
			if (search1->StaInfo.State == ASSOCIATED)
				buf[j++] = TRUE;
			else
				buf[j++] = FALSE;

#ifdef STA_INFO_DB
			buf[j++] = search1->StaInfo.ClientMode;
			buf[j++] = search1->StaInfo.Rate;
			buf[j++] = search1->StaInfo.Sq2;
			buf[j++] = search1->StaInfo.Sq1;
			buf[j++] = search1->StaInfo.RSSI;
			if (search1->StaInfo.PwrMode == PWR_MODE_PWR_SAVE)
				buf[j++] = TRUE;
			else
				buf[j++] = FALSE;
#endif
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (1);

}

extern UINT16 extStaDb_list2(vmacApInfo_t * vmac_p, UINT8 * buf, UINT8 get)
{
	int j;
	ListItem *search;
	ExtStaInfoItem_t *search1;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	j = 0;

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;

		if (1		     /** (search1->StaInfo.AP == FALSE) && (
					(search1->StaInfo.State == AUTHENTICATED) ||  //removed for now JS
					(search1->StaInfo.State == ASSOCIATED))
					&& (!memcmp(&vmac_p->macBssId, &search1->StaInfo.Bssid,sizeof(IEEEtypes_MacAddr_t)))**/ ) {
			/*station mac address */
			buf[j++] = search1->StaInfo.Addr[0];
			buf[j++] = search1->StaInfo.Addr[1];
			buf[j++] = search1->StaInfo.Addr[2];
			buf[j++] = search1->StaInfo.Addr[3];
			buf[j++] = search1->StaInfo.Addr[4];
			buf[j++] = search1->StaInfo.Addr[5];
#ifndef STA_INFO_DB
			buf[j++] = 0;
#endif
			/*station association state */
			if (search1->StaInfo.State == ASSOCIATED)
				buf[j++] = TRUE;
			else
				buf[j++] = FALSE;

#ifdef STA_INFO_DB
			buf[j++] = search1->StaInfo.ClientMode;
			buf[j++] = search1->StaInfo.Rate;
			buf[j++] = search1->StaInfo.Sq2;
			buf[j++] = search1->StaInfo.Sq1;
			buf[j++] = search1->StaInfo.RSSI;
			if (search1->StaInfo.PwrMode == PWR_MODE_PWR_SAVE)
				buf[j++] = TRUE;
			else
				buf[j++] = FALSE;
#endif
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (1);

}

extern UINT16 extStaDb_AggrCk(vmacApInfo_t * vmac_p)
{
	ListItem *search;
	ExtStaInfoItem_t *search1;
	vmacApInfo_t *vmacSta_p;
	Aggr11n *pAggr11n;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
		pAggr11n = &search1->StaInfo.aggr11n;
#ifndef AMSDUOVERAMPDU
		if ((pAggr11n->type & WL_WLAN_TYPE_AMSDU) && (*(search1->StaInfo.mib_p->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK)) {
			if (pAggr11n->threshold && (pAggr11n->txcnt > pAggr11n->threshold)) {
				pAggr11n->start = AGGKEEPNUM;
			} else {
				if (pAggr11n->start != 0)
					pAggr11n->start--;
			}
		}
#endif
		{
			int tid;
			if (*(search1->StaInfo.mib_p->mib_AmpduTx) == 3)
				for (tid = 0; tid < 7; tid++) {

					if (pAggr11n->threshold && (pAggr11n->txcntbytid[tid] > pAggr11n->threshold)) {
						pAggr11n->onbytid[tid] = 1;
					} else {
						if (pAggr11n->threshold && (pAggr11n->txcntbytid[tid] < 4)) {
							//disableAmpduTx(vmacSta_p,search1->StaInfo.Addr, tid);
							pAggr11n->onbytid[tid] = 0;
							//search1->StaInfo.aggr11n.startbytid[tid]=0;
						}
					}
					pAggr11n->txcntbytid[tid] = 0;
				}
		}
		pAggr11n->txcnt = 0;
		search = search->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (1);
}

extern UINT16 extStaDb_AggrFrameCk(vmacApInfo_t * vmac_p, int force)
{
	int retval = 0;
	ListItem *search;
	ExtStaInfoItem_t *search1;
	vmacApInfo_t *vmacSta_p;
	unsigned long flags;
	//unsigned long dbflags;
	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!(vmac_p->dev->flags & IFF_RUNNING))
		return 0;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	//SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
		if (*(search1->StaInfo.mib_p->QoSOptImpl) && (search1->StaInfo.aggr11n.type & WL_WLAN_TYPE_AMSDU))	//search1->StaInfo.aggr11n.threshold)
		{
			SPIN_LOCK_IRQSAVE(&search1->StaInfo.aggr11n.Lock, flags);
			{
#ifdef WDS_FEATURE
				struct net_device *dev = (struct net_device *)(search1->StaInfo.wdsInfo);
				if (dev)
					retval = send_11n_aggregation_skb(dev, &search1->StaInfo, force);
				else
#endif
					retval = send_11n_aggregation_skb(search1->StaInfo.dev, &search1->StaInfo, force);
			}
			SPIN_UNLOCK_IRQRESTORE(&search1->StaInfo.aggr11n.Lock, flags);
		}
		search = search->nxt;
	}
	//SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return retval;
}

/*This function cleans up and send deauth msg to sta*/
extern extStaDb_Status_e extStaDb_RemoveStaNSendDeauthMsg(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	extStaDb_StaInfo_t *StaInfo_p;
	vmacApInfo_t *vmacSta_p;
	//unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	//SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, Addr_p, STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
		/* Station not known, do nothing */
		return LOCATE_FAILURE;
	}
	if (StaInfo_p->AP == TRUE) {
		return LOCATE_FAILURE;
	}
#ifdef AP_URPTR
	/* Clean up UR hash table for this STA */
	urHash_RemoveSta(vmacSta_p, Addr_p, 0);
#endif
	if (StaInfo_p->State == ASSOCIATED) {
		disableAmpduTxMacAddr(vmac_p, (UINT8 *) Addr_p);
#ifdef SOC_W906X
		macMgmtMlme_SendDeauthenticateMsg(vmac_p, Addr_p, StaInfo_p->StnId, IEEEtypes_REASON_DISASSOC_INACTIVE, TRUE);
#else
		macMgmtMlme_SendDeauthenticateMsg(vmac_p, Addr_p, StaInfo_p->StnId, IEEEtypes_REASON_DISASSOC_INACTIVE);
#endif
		FreeAid(vmacSta_p, StaInfo_p->Aid);
		ResetAid(vmacSta_p, StaInfo_p->StnId, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
	}
	if (StaInfo_p->PwrMode == PWR_MODE_PWR_SAVE) {
		if (vmac_p->PwrSaveStnCnt)
			vmac_p->PwrSaveStnCnt--;
		StaInfo_p->PwrMode = PWR_MODE_ACTIVE;
	}
	if (StaInfo_p->ClientMode == BONLY_MODE)
		macMgmtMlme_DecrBonlyStnCnt(vmac_p, 0);

	if (!StaInfo_p->CapInfo.ShortPreamble)
		macMgmtMlme_DecrBarkerPreambleStnCnt(vmacSta_p);

	if (StaInfo_p->Aid != 0) {
		FreeAid(vmac_p, StaInfo_p->Aid);
		ResetAid(vmac_p, StaInfo_p->StnId, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
	}
	StaInfo_p->State = UNAUTHENTICATED;

//      SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);    
	extStaDb_DelSta(vmac_p, Addr_p, STADB_DONT_UPDATE_AGINGTIME);
	FreeStnId(vmac_p, StaInfo_p->StnId);
	wlFwSetNewStn(vmac_p->dev, (u_int8_t *) Addr_p, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
	return (DEL_SUCCESS);
}

/*!
* Remove a station from the station database plus cleanup
* @param Addr_p Pointer to the station mac address
* @return DEL_SUCCESS,      
*         LOCATE_FAILURE          
*/
extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	extStaDb_StaInfo_t *StaInfo_p;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, Addr_p, STADB_NO_BLOCK)) == NULL) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		/* Station not known, do nothing */
		return LOCATE_FAILURE;
	}
	if (StaInfo_p->AP == TRUE) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return LOCATE_FAILURE;
	}
#ifdef AP_URPTR
	/* Clean up UR hash table for this STA */
	urHash_RemoveSta(vmacSta_p, Addr_p, 1);
#endif
	if (StaInfo_p->State == ASSOCIATED) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		macMgmtCleanUp(vmac_p, StaInfo_p);
		SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	}
	FreeAid(vmac_p, StaInfo_p->Aid);
	StaInfo_p->Aid = 0;
	StaInfo_p->State = UNAUTHENTICATED;
	FreeStnId(vmac_p, StaInfo_p->StnId);
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	extStaDb_DelSta(vmac_p, Addr_p, STADB_DONT_UPDATE_AGINGTIME);
	wlFwSetNewStn(vmac_p->dev, (u_int8_t *) Addr_p, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
	return (DEL_SUCCESS);

}

UINT8 GetAssociateMacAddress(vmacApInfo_t * vmac_p, unsigned char *MacAddress)
{
	ListItem *search;
	ExtStaInfoItem_t *search1;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
		if ((search1->StaInfo.State == ASSOCIATED)) {
			memcpy(MacAddress, search1->StaInfo.Addr, 6);
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
			return 1;
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return 0;

}

void extStaDb_SetNewState4AllSta(vmacApInfo_t * vmac_p, extStaDb_State_e NewState)
{
	vmacApInfo_t *vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	ExtStaInfoItem_t *Curr_p, *Item_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr), STADB_NO_BLOCK))) {
			if (StaInfo_p->State == ASSOCIATED) {
				StaInfo_p->State = NewState;
				if (NewState != ASSOCIATED) {
					StaInfo_p->keyMgmtStateInfo.RSNDataTrafficEnabled = 0;
				}
				if (NewState == AUTHENTICATED) {
					FreeAid(vmacSta_p, StaInfo_p->Aid);
					StaInfo_p->Aid = 0;
				}
#ifdef QOS_FEATURE
				if (NewState == UNAUTHENTICATED) {
					StaInfo_p->IsStaQSTA = FALSE;
				}
#endif

			}
		}
		Curr_p = Curr_p->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

void extStaDb_SendGrpKeyMsgToAllSta(vmacApInfo_t * vmac_p)
{
	MhsmEvent_t msg;
	vmacApInfo_t *vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	ExtStaInfoItem_t *Curr_p, *Item_p;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	SPIN_LOCK_BH(&vmacSta_p->StaCtl->dbLock);
	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		if ((StaInfo_p = extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr), STADB_NO_BLOCK))) {
			if (StaInfo_p->State == ASSOCIATED) {
				msg.event = GRPKEYTIMEOUT_EVT;
#ifdef AP_MAC_LINUX
				msg.devinfo = (void *)vmac_p;
#endif
				//ProcessKeyMgmtData(vmac_p,NULL, &StaInfo_p->Addr, &msg);
				if (StaInfo_p->keyMgmtHskHsm.super.pCurrent != NULL) {
					mhsm_send_event(&StaInfo_p->keyMgmtHskHsm.super, &msg);	//Pete
				}
			}
		}
		Curr_p = Curr_p->nxt;
	}
	SPIN_UNLOCK_BH(&vmacSta_p->StaCtl->dbLock);
}

extern extStaDb_Status_e extStaDb_SetRSNDataTrafficEnabled(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 value)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	//    item_p->StaInfo.keyMgmtStateInfo->RSNDataTrafficEnabled = value;
	item_p->StaInfo.keyMgmtStateInfo.RSNDataTrafficEnabled = value;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extStaDb_Status_e extStaDb_SetRSNPwkAndDataTraffic(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p,
						   UINT8 * pEncryptKey, UINT32 * pTxMICKey, UINT32 * pRxMICKey)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	/*    item_p->StaInfo.keyMgmtStateInfo->RSNDataTrafficEnabled = TRUE;
	   memcpy(item_p->StaInfo.keyMgmtStateInfo->u.RSNPwkEncryptKey, pEncryptKey, 16);
	   memcpy(item_p->StaInfo.keyMgmtStateInfo->RSNPwkTxMICKey, pTxMICKey, 8);
	   memcpy(item_p->StaInfo.keyMgmtStateInfo->RSNPwkRxMICKey, pRxMICKey, 8);
	 */
	item_p->StaInfo.keyMgmtStateInfo.RSNDataTrafficEnabled = TRUE;
	//memcpy(item_p->StaInfo.keyMgmtStateInfo.tk1.RSNPwkEncryptKey, pEncryptKey, 16);
	memcpy(item_p->StaInfo.keyMgmtStateInfo.PairwiseTempKey1, pEncryptKey, TK_SIZE_MAX);
	memcpy(item_p->StaInfo.keyMgmtStateInfo.RSNPwkTxMICKey, pTxMICKey, 8);
	memcpy(item_p->StaInfo.keyMgmtStateInfo.RSNPwkRxMICKey, pRxMICKey, 8);
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	//#endif
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_SetRSNPwk(vmacApInfo_t * vmac_p,
					    IEEEtypes_MacAddr_t * Addr_p, UINT8 * pEncryptKey, UINT32 * pTxMICKey, UINT32 * pRxMICKey)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	memcpy(item_p->StaInfo.keyMgmtStateInfo.PairwiseTempKey1, pEncryptKey, TK_SIZE_MAX);
	memcpy(item_p->StaInfo.keyMgmtStateInfo.RSNPwkTxMICKey, pTxMICKey, 8);
	memcpy(item_p->StaInfo.keyMgmtStateInfo.RSNPwkRxMICKey, pRxMICKey, 8);
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_SetRSNPmk(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 * pPMK)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	memcpy(item_p->StaInfo.keyMgmtStateInfo.PMK, pPMK, 32);
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_GetRSN_IE(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 * RsnIE_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Get the value. */
	/*------------------------*/
	memcpy((UINT8 *) RsnIE_p, item_p->StaInfo.keyMgmtStateInfo.RsnIEBuf, 2 + *(item_p->StaInfo.keyMgmtStateInfo.RsnIEBuf + 1));
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

#ifdef MRVL_80211R
extern extStaDb_Status_e extStaDb_Get_11r_IEs(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 * iebuf, UINT16 * len, UINT8 * reassoc)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Get the value. */
	/*------------------------*/
	if (item_p->StaInfo.keyMgmtStateInfo.mdie_buf[0] == MD_IE && item_p->StaInfo.keyMgmtStateInfo.mdie_buf[1] == 3) {
		memcpy((UINT8 *) iebuf, item_p->StaInfo.keyMgmtStateInfo.mdie_buf, 2 + *(item_p->StaInfo.keyMgmtStateInfo.mdie_buf + 1));
		*len = (iebuf[1] + 2);
	} else {
		*len = 0;
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return NOT_INITIALIZED;
	}
	if (item_p->StaInfo.keyMgmtStateInfo.ftie_buf[0] == FT_IE && item_p->StaInfo.keyMgmtStateInfo.ftie_buf[1] != 0) {
		memcpy((UINT8 *) & iebuf[*len], item_p->StaInfo.keyMgmtStateInfo.ftie_buf, 2 + *(item_p->StaInfo.keyMgmtStateInfo.ftie_buf + 1));
		*len += (item_p->StaInfo.keyMgmtStateInfo.ftie_buf[1] + 2);
	}
	*reassoc = item_p->StaInfo.keyMgmtStateInfo.reassoc;
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}
#endif

#ifdef MRVL_WSC			//MRVL_WSC_IE
extern extStaDb_Status_e extStaDb_GetWSC_IE(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 * WscIE_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Get the value. */
	/*------------------------*/
	memcpy((UINT8 *) WscIE_p, &item_p->StaInfo.WscIEBuf, 2 + item_p->StaInfo.WscIEBuf.Len);
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}
#endif				//WSC_MRVL_IE

extern extStaDb_Status_e extStaDb_SetRSN_IE(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, IEEEtypes_RSN_IE_t * RsnIE_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	UINT8 RsnIELen;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	RsnIELen = *((UINT8 *) RsnIE_p + 1);
	if ((RsnIELen + 2) <= MAX_SIZE_RSN_IE_BUF) {
		memset(item_p->StaInfo.keyMgmtStateInfo.RsnIEBuf, 0, MAX_SIZE_RSN_IE_BUF);
		memcpy((UINT8 *) item_p->StaInfo.keyMgmtStateInfo.RsnIEBuf, RsnIE_p, RsnIELen + 2);
	} else {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (RSN_IE_BUF_OVERFLOW);
	}

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_GetPairwiseTSC(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT32 * pTxIV32, UINT16 * pTxIV16)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Get the value. */
	/*------------------------*/
	*pTxIV32 = item_p->StaInfo.keyMgmtStateInfo.TxIV32;
	*pTxIV16 = item_p->StaInfo.keyMgmtStateInfo.TxIV16;
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_SetPairwiseTSC(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT32 TxIV32, UINT16 TxIV16)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Get the value. */
	/*------------------------*/
	item_p->StaInfo.keyMgmtStateInfo.TxIV32 = TxIV32;
	item_p->StaInfo.keyMgmtStateInfo.TxIV16 = TxIV16;
	item_p->StaInfo.keyMgmtStateInfo.RxIV32 = 0xFFFFFFFF;	//Rahul
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extStaDb_Status_e extStaDb_GetStaInfoAndTxKeys(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p,
					       extStaDb_StaInfo_t * StaInfo_p, UINT32 AgingTimeMode)
{
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/* if not found, give back the semaphore and return error status.   */
	/*------------------------------------------------------------------*/
	if (LocateAddr(vmacSta_p, Addr_p, &item_p, &idx) == LOCATE_SUCCESS) {
		/*-------------------------------------------*/
		/* Fill out the requested state information. */
		/*-------------------------------------------*/
		//*StaInfo_p = item_p->StaInfo;
		memcpy(StaInfo_p, &item_p->StaInfo, sizeof(extStaDb_StaInfo_t) - sizeof(keyMgmtInfo_t));

		memcpy(StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1, item_p->StaInfo.keyMgmtStateInfo.PairwiseTempKey1, TK_SIZE_MAX);
		memcpy(StaInfo_p->keyMgmtStateInfo.RSNPwkTxMICKey, item_p->StaInfo.keyMgmtStateInfo.RSNPwkTxMICKey, 8);
		StaInfo_p->keyMgmtStateInfo.TxIV32 = item_p->StaInfo.keyMgmtStateInfo.TxIV32;
		StaInfo_p->keyMgmtStateInfo.TxIV16 = item_p->StaInfo.keyMgmtStateInfo.TxIV16;
		memcpy(StaInfo_p->keyMgmtStateInfo.Phase1KeyTx, item_p->StaInfo.keyMgmtStateInfo.Phase1KeyTx, 10);
		StaInfo_p->QueueToUse = item_p->StaInfo.QueueToUse;
		StaInfo_p->keyMgmtStateInfo.RSNDataTrafficEnabled = item_p->StaInfo.keyMgmtStateInfo.RSNDataTrafficEnabled;
		memcpy(StaInfo_p->keyMgmtStateInfo.RsnIEBuf, item_p->StaInfo.keyMgmtStateInfo.RsnIEBuf, MAX_SIZE_RSN_IE_BUF);
		//StaInfo_p->ClientMode=item_p->StaInfo.ClientMode;
		//StaInfo_p->ApMode = item_p->StaInfo.ApMode;
		//Increment the counters
		item_p->StaInfo.keyMgmtStateInfo.TxIV16++;
		if (item_p->StaInfo.keyMgmtStateInfo.TxIV16 == 0) {
			item_p->StaInfo.keyMgmtStateInfo.TxIV32++;
		}
		StaInfo_p->QueueToUse = item_p->StaInfo.QueueToUse;
		switch (AgingTimeMode) {
		case 0:
			break;
		case 1:
			item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes;	// AGING_TIME;
		case 2:
			if (item_p->StaInfo.TimeStamp > 2)
				item_p->StaInfo.TimeStamp = 2;	// minimum unit
			break;
		default:
			break;
		}
		/*-------------------------------------------------------*/
		/* Finished - give back the semaphore and return status. */
		/*-------------------------------------------------------*/
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (STATE_SUCCESS);
	} else {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return LOCATE_FAILURE;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

extStaDb_Status_e extStaDb_GetRSNPwk(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 * pEncryptKey, UINT32 * pTxMICKey, UINT32 * pRxMICKey)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	/*    memcpy(pEncryptKey, item_p->StaInfo.keyMgmtStateInfo->u.RSNPwkEncryptKey, 16);
	   memcpy(pTxMICKey, item_p->StaInfo.keyMgmtStateInfo->RSNPwkTxMICKey, 8);
	   memcpy(pRxMICKey, item_p->StaInfo.keyMgmtStateInfo->RSNPwkRxMICKey, 8);
	 */
	//memcpy(pEncryptKey, item_p->StaInfo.keyMgmtStateInfo.tk1.RSNPwkEncryptKey, 16);
	memcpy(pEncryptKey, item_p->StaInfo.keyMgmtStateInfo.PairwiseTempKey1, TK_SIZE_MAX);
	memcpy(pTxMICKey, item_p->StaInfo.keyMgmtStateInfo.RSNPwkTxMICKey, 8);
	memcpy(pRxMICKey, item_p->StaInfo.keyMgmtStateInfo.RSNPwkRxMICKey, 8);
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
#ifndef AP32GST
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);	//masked by laser
#endif
	return (STATE_SUCCESS);
}

extStaDb_Status_e extStaDb_GetStaInfoAndRxKeys(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p,
					       extStaDb_StaInfo_t * StaInfo_p, UINT32 AgingTimeMode)
{
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);	//masked laser for GST
#endif

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/* if not found, give back the semaphore and return error status.   */
	/*------------------------------------------------------------------*/
	if (LocateAddr(vmacSta_p, Addr_p, &item_p, &idx) == LOCATE_SUCCESS) {
		/*-------------------------------------------*/
		/* Fill out the requested state information. */
		/*-------------------------------------------*/
		//*StaInfo_p = item_p->StaInfo;
		memcpy(StaInfo_p, &item_p->StaInfo, sizeof(extStaDb_StaInfo_t) - sizeof(keyMgmtInfo_t));

		memcpy(StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1, item_p->StaInfo.keyMgmtStateInfo.PairwiseTempKey1, TK_SIZE_MAX);

		memcpy(StaInfo_p->keyMgmtStateInfo.RSNPwkRxMICKey, item_p->StaInfo.keyMgmtStateInfo.RSNPwkRxMICKey, 8);
		memcpy(StaInfo_p->keyMgmtStateInfo.Phase1KeyRx, item_p->StaInfo.keyMgmtStateInfo.Phase1KeyRx, 10);
		StaInfo_p->keyMgmtStateInfo.RSNDataTrafficEnabled = item_p->StaInfo.keyMgmtStateInfo.RSNDataTrafficEnabled;
		StaInfo_p->keyMgmtStateInfo.RxIV32 = item_p->StaInfo.keyMgmtStateInfo.RxIV32;

		if (AgingTimeMode == 2) {	// mimimum set aging time
			if (item_p->StaInfo.TimeStamp > 2)
				item_p->StaInfo.TimeStamp = 2;	// minimum unit
		} else if (AgingTimeMode == 1) {	// maxmum set aging time
			if (StaInfo_p->ClientMode == BONLY_MODE) {
				item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes;	// AGING_TIME;
			} else {
				item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes * 15;
			}
		}
		/*-------------------------------------------------------*/
		/* Finished - give back the semaphore and return status. */
		/*-------------------------------------------------------*/
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (STATE_SUCCESS);
	} else {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return LOCATE_FAILURE;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

extStaDb_Status_e extStaDb_GetKeyMgmtInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, keyMgmtInfo_t * KeyMgmtInfo)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	memcpy(KeyMgmtInfo, &(item_p->StaInfo.keyMgmtStateInfo), sizeof(keyMgmtInfo_t));

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
#ifndef AP32GST
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
	return (STATE_SUCCESS);
}

extStaDb_Status_e extStaDb_SetKeyMgmtInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, keyMgmtInfo_t * pKeyMgmtInfo)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	memcpy(&(item_p->StaInfo.keyMgmtStateInfo), pKeyMgmtInfo, sizeof(keyMgmtInfo_t));

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

#ifdef QOS_FEATURE

UINT8 extStaDb_GetQoSOptn(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	UINT8 QosOptn;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		//     return(NOT_INITIALIZED);
		return (0);	//return 0 for now, should not matter for caller of this function. original function not well written
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		//  return(result);
		return (0);	//return 0 for now, should not matter for caller of this function. original function not well written
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	QosOptn = item_p->StaInfo.IsStaQSTA;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
#ifndef AP32GST
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
	//    return(STATE_SUCCESS);
	return (QosOptn);

}

extern extStaDb_Status_e extStaDb_SetQoSOptn(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT8 QosOptn)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	item_p->StaInfo.IsStaQSTA = QosOptn;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
#ifndef AP32GST
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
	return (STATE_SUCCESS);
}

#endif

#ifdef WMM_PS_SUPPORT
extern extStaDb_Status_e extStaDb_SetQosInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, QoS_WmeInfo_Info_t * pQosinfo)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	item_p->StaInfo.Qosinfo = *pQosinfo;

	/** when a u-apsd flag is set to 1, it indicates that the corresponding AC is both a delivery-enabled AC and triggered
	enabled AC **/

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_GetWMM_DeliveryEnableInfo(vmacApInfo_t * vmac_p,
							    IEEEtypes_MacAddr_t * Addr_p, UINT8 Priority, UINT8 * Wmm_DeliveryInfo, UINT8 * UpdateTim)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	*Wmm_DeliveryInfo = 0;
	*UpdateTim = 0;
	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	switch (AccCategoryQ[Priority]) {
		/** BG traffic **/
	case 0:
		if (item_p->StaInfo.Qosinfo.Uapsd_ac_be)
			*Wmm_DeliveryInfo = 1;
		break;
	case 1:
		if (item_p->StaInfo.Qosinfo.Uapsd_ac_bk)
			*Wmm_DeliveryInfo = 1;
		break;
	case 2:
		if (item_p->StaInfo.Qosinfo.Uapsd_ac_vi)
			*Wmm_DeliveryInfo = 1;
		break;
	case 3:
		if (item_p->StaInfo.Qosinfo.Uapsd_ac_vo)
			*Wmm_DeliveryInfo = 1;
		break;
	}

	/** 3.6.1.4 In case all ACs are delivery-enabled ACs, WMM AP with the U-APSD bit7 set to 1 in the
	Qos Info Field shall assembled the Partial Virtual Bitmap containing the buffer status for all AC
	per destination for WMM Sta **/
	if ((item_p->StaInfo.Qosinfo.Uapsd_ac_be && item_p->StaInfo.Qosinfo.Uapsd_ac_bk
	     && item_p->StaInfo.Qosinfo.Uapsd_ac_vi && item_p->StaInfo.Qosinfo.Uapsd_ac_vo) || *Wmm_DeliveryInfo == 0)
		*UpdateTim = 1;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

extern UINT8 extStaDb_Check_Uapsd_Capability(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (1);
	}

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (1);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/

	/** 3.6.1.4 In case all ACs are delivery-enabled ACs, WMM AP with the U-APSD bit7 set to 1 in the
	Qos Info Field shall assembled the Partial Virtual Bitmap containing the buffer status for all AC
	per destination for WMM Sta **/
	if ((item_p->StaInfo.Qosinfo.Uapsd_ac_be || item_p->StaInfo.Qosinfo.Uapsd_ac_bk
	     || item_p->StaInfo.Qosinfo.Uapsd_ac_vi || item_p->StaInfo.Qosinfo.Uapsd_ac_vo)) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return 1;
	}

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (0); /** not all ac are delivery enable **/
}

extern UINT8 extStaDb_Check_ALL_AC_DeliveryEnableInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (1);
	}
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (1);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/

	/** 3.6.1.4 In case all ACs are delivery-enabled ACs, WMM AP with the U-APSD bit7 set to 1 in the
	Qos Info Field shall assembled the Partial Virtual Bitmap containing the buffer status for all AC
	per destination for WMM Sta **/
	if ((item_p->StaInfo.Qosinfo.Uapsd_ac_be && item_p->StaInfo.Qosinfo.Uapsd_ac_bk
	     && item_p->StaInfo.Qosinfo.Uapsd_ac_vi && item_p->StaInfo.Qosinfo.Uapsd_ac_vo)) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return 1;
	}

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (0); /** not all ac are delivery enable **/
}

#endif

extStaDb_Status_e extStaDb_SetPhase1Key(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, UINT16 * Phase1Key, PacketType_e mode, UINT32 RxIV32)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	if (mode == Tx)
		memcpy(item_p->StaInfo.keyMgmtStateInfo.Phase1KeyTx, Phase1Key, 10);
	//(*my_memcpyFp)(item_p->StaInfo.keyMgmtStateInfo.Phase1KeyTx, Phase1Key, 10);
	else {
		memcpy(item_p->StaInfo.keyMgmtStateInfo.Phase1KeyRx, Phase1Key, 10);
		item_p->StaInfo.keyMgmtStateInfo.RxIV32 = RxIV32;
	}
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (STATE_SUCCESS);
}

int StnMacAddressCopy(vmacApInfo_t * vmac_p, unsigned char *tempmac)
{
	int i = 0;
	vmacApInfo_t *vmacSta_p;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	for (i = 0; i < 32; i++) {
		memcpy((tempmac + i * 6), vmacSta_p->StaCtl->ExtStaInfoDb[i].StaInfo.Addr, 6);

		if (is_zero_ether_addr(tempmac + i * 6))
			return i;

	}
	return i;

}

extern extStaDb_Status_e extStaDb_UpdateAgingTime(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}

	/*------------------------*/
	/* Update the power mode. */
	/*------------------------*/
	item_p->StaInfo.TimeStamp = vmacSta_p->StaCtl->aging_time_in_minutes * 15;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (STATE_SUCCESS);
}

extStaDb_Status_e extStaDb_GetStaInfo_noWait(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p,
					     extStaDb_StaInfo_t * StaInfo_p, UINT32 AgingTimeMode)
{
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	//SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);         
#endif

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/* if not found, give back the semaphore and return error status.   */
	/*------------------------------------------------------------------*/
	if (LocateAddr(vmacSta_p, Addr_p, &item_p, &idx) == LOCATE_SUCCESS) {
		/*-------------------------------------------*/
		/* Fill out the requested state information. */
		/*-------------------------------------------*/
		//*StaInfo_p = item_p->StaInfo;

		StaInfo_p->QueueToUse = item_p->StaInfo.QueueToUse;
		StaInfo_p->IsStaQSTA = item_p->StaInfo.IsStaQSTA;
		StaInfo_p->Aid = item_p->StaInfo.Aid;

		/*-------------------------------------------------------*/
		/* Finished - give back the semaphore and return status. */
		/*-------------------------------------------------------*/
#ifndef AP32GST
		// SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);   
#endif
		return (STATE_SUCCESS);
	} else {
#ifndef AP32GST
		// SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);  
#endif
		return LOCATE_FAILURE;
	}
}

extern int set_sta_aging_time(vmacApInfo_t * vmac_p, int minutes)
{
	vmacApInfo_t *vmacSta_p;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	vmacSta_p->StaCtl->aging_time_in_minutes = minutes * 60 / AGING_TIMER_VALUE_IN_SECONDS;
	return minutes;
}

#ifdef FLEX_TIME
/** Get AGAssociation cnt **/

void extStaDb_AGStnsCnt(vmacApInfo_t * vmac_p)
{
	int j;
	ListItem *search;
	ExtStaInfoItem_t *search1;
	UINT8 tempAOnlyClientCnt, tempBGOnlyClientCnt;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	j = 0;
	tempAOnlyClientCnt = tempBGOnlyClientCnt = 0;
	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
		if ((search1->StaInfo.AP == FALSE) && ((search1->StaInfo.State == ASSOCIATED))) {
			if (search1->StaInfo.ClientMode == AONLY_MODE) {
				tempAOnlyClientCnt++;

			} else {
				tempBGOnlyClientCnt++;

			}
		}
		search = search->nxt;
	}

	AOnlyClientCnt = tempAOnlyClientCnt;
	BGOnlyClientCnt = tempBGOnlyClientCnt;
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (1);
}
#endif
#ifdef IEEE80211H
extern extStaDb_Status_e extStaDb_GetMeasurementInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, extStaDb_measurement_info_t * measureInfo_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	*measureInfo_p = item_p->StaInfo.measureInfo;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
#ifndef AP32GST
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
	return (STATE_SUCCESS);
}

extern extStaDb_Status_e extStaDb_SetMeasurementInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, extStaDb_measurement_info_t * measureInfo_p)
{
	extStaDb_Status_e result;
	ExtStaInfoItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	if (!vmacSta_p->StaCtl->Initialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
#ifndef AP32GST
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif

	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be updated; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	if ((result = LocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
#ifndef AP32GST
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
		return (result);
	}

	/*------------------------*/
	/* Update the value. */
	/*------------------------*/
	item_p->StaInfo.measureInfo = *measureInfo_p;

	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
#ifndef AP32GST
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
#endif
	return (STATE_SUCCESS);
}

#endif
#ifdef INTOLERANT40
void extStaDb_SendBeaconReqMeasureReqAction(vmacApInfo_t * vmac_p)
{
	extern BOOLEAN macMgmtMlme_SendBeaconReqMeasureReqAction(struct net_device *dev, IEEEtypes_MacAddr_t * Addr);
	ListItem *search;
	ExtStaInfoItem_t *search1;
	vmacApInfo_t *vmacSta_p;

	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return (0);
	}

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		search1 = (ExtStaInfoItem_t *) search;
		if ((search1->StaInfo.AP == FALSE) && (search1->StaInfo.State == ASSOCIATED) && (search1->StaInfo.ClientMode == NONLY_MODE)) {
			macMgmtMlme_SendBeaconReqMeasureReqAction(vmac_p->dev, (IEEEtypes_MacAddr_t *) search1->StaInfo.Addr);
		}
		search = search->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}
#endif

WL_STATUS ethStaDb_Init(vmacApInfo_t * vmacSta_p, UINT16 MaxStns)
{
	UINT32 i;

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmacSta_p->master)
			return (OS_SUCCESS);
	}

	if (vmacSta_p->EthStaCtl == NULL) {
		vmacSta_p->EthStaCtl = (struct ETHSTADB_CTL *)wl_kmalloc_autogfp(sizeof(struct ETHSTADB_CTL));

		if (vmacSta_p->EthStaCtl == NULL) {
			printk("fail to alloc memory\n");
			return OS_FAIL;
		}
		memset(vmacSta_p->EthStaCtl, 0, sizeof(struct ETHSTADB_CTL));
	}
	vmacSta_p->EthStaCtl->aging_time_in_minutes = 3 * 60 / AGING_TIMER_VALUE_IN_SECONDS;

	/*pre-allocate sta datebase */
	if (vmacSta_p->EthStaCtl->EthStaDb == NULL) {
		vmacSta_p->EthStaCtl->EthStaDb = (EthStaItem_t *) wl_kmalloc_autogfp(MaxStns * sizeof(EthStaItem_t));
		if (vmacSta_p->EthStaCtl->EthStaDb == NULL) {
			printk("fail to alloc memory\n");
			return OS_FAIL;
		}
		memset(vmacSta_p->EthStaCtl->EthStaDb, 0, MaxStns * sizeof(EthStaItem_t));

	}

	/*----------------------------------------------------------------*/
	/* Initial the array of pointers to station information elements; */
	/* initially, the pointers all point to nothing.                  */
	/*----------------------------------------------------------------*/
	for (i = 0; i < EXT_STA_TABLE_SIZE_RUNNING; i++) {
		vmacSta_p->EthStaCtl->EthStaDb_p[i] = NULL;
	}

	ListInit(&vmacSta_p->EthStaCtl->FreeEthStaList);
	ListInit(&vmacSta_p->EthStaCtl->EthStaList);
	/*-------------------------------------------------------------*/
	/* Set up the list of initially free elements that are used to */
	/* record external station information.                        */
	/*-------------------------------------------------------------*/
	for (i = 0; i < MaxStns; i++) {
		vmacSta_p->EthStaCtl->EthStaDb[i].nxt = NULL;
		vmacSta_p->EthStaCtl->EthStaDb[i].prv = NULL;
		vmacSta_p->EthStaCtl->EthStaDb[i].nxt_ht = NULL;
		vmacSta_p->EthStaCtl->EthStaDb[i].prv_ht = NULL;
		vmacSta_p->EthStaCtl->EthStaDb[i].ethStaInfo.TimeStamp = 30;
		vmacSta_p->EthStaCtl->EthStaDb[i].ethStaInfo.pStaInfo_t = NULL;
		memset(&vmacSta_p->EthStaCtl->EthStaDb[i].ethStaInfo.Addr, 0, sizeof(IEEEtypes_MacAddr_t));
		ListPutItem(&vmacSta_p->EthStaCtl->FreeEthStaList, (ListItem *) (vmacSta_p->EthStaCtl->EthStaDb + i));
	}

	vmacSta_p->EthStaCtl->eInitialized = TRUE;

	return (OS_SUCCESS);
}

static extStaDb_Status_e EthStaLocateAddr(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, EthStaItem_t ** Item_pp, UINT32 * Idx_p)
{
	UINT32 key;
	vmacApInfo_t *vmacSta_p = vmac_p;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}

	/*---------------------------------------------------------------------*/
	/* First, get the lower 32 bits of the MAC address to use for hashing. */
	/*---------------------------------------------------------------------*/
	memcpy(&key, ((IEEEtypes_Addr_t *) Addr_p + 2 * sizeof(IEEEtypes_Addr_t)), 4 * sizeof(IEEEtypes_Addr_t));
	/*-----------------------------------------------------------*/
	/* Next, hash to get an index into the table that stores MAC */
	/* addresses and associated information.                     */
	/*-----------------------------------------------------------*/
	*Idx_p = Hash(key);

	/*-------------------------------------------------*/
	/* Now see if the address is already in the table. */
	/*-------------------------------------------------*/
	*Item_pp = vmacSta_p->EthStaCtl->EthStaDb_p[*Idx_p];
	if (*Item_pp == NULL) {
		return (LOCATE_FAILURE);
	} else {
		if (!memcmp((*Item_pp)->ethStaInfo.Addr, Addr_p, 6 * sizeof(IEEEtypes_Addr_t))) {
			return (LOCATE_SUCCESS);
		} else {
			while ((*Item_pp)->nxt_ht != NULL) {
				*Item_pp = (*Item_pp)->nxt_ht;

				if (!memcmp((*Item_pp)->ethStaInfo.Addr, Addr_p, 6 * sizeof(IEEEtypes_Addr_t))) {
					return (LOCATE_SUCCESS);
				}
			}
		}
	}

	return (LOCATE_FAILURE);
}

extStaDb_Status_e ethStaDb_AddSta(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, extStaDb_StaInfo_t * StaInfo_p)
{
	extStaDb_Status_e result;
	EthStaItem_t *item_p = NULL;
	UINT32 idx;
	ListItem *tmp;
	vmacApInfo_t *vmacSta_p = vmac_p;

	unsigned long dbflags;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}

	if (!vmacSta_p->EthStaCtl->eInitialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find a spot where the station that is to be added  */
	/* can be placed; if the station is already in the table, give back */
	/* the semaphore and return status.                                 */
	/*------------------------------------------------------------------*/
	if ((result = EthStaLocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_FAILURE) {
		/* Update source path only */
		item_p->ethStaInfo.pStaInfo_t = StaInfo_p;
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (STATION_EXISTS_ERROR);
	}

	/*---------------------------------------------------------------*/
	/* Get a structure off of the free list, fill it out with the    */
	/* information about the new station, and put it in the location */
	/* found above.                                                  */
	/*---------------------------------------------------------------*/

	tmp = ListGetItem(&vmacSta_p->EthStaCtl->FreeEthStaList);
	if (tmp) {
		EthStaItem_t *search_p = vmacSta_p->EthStaCtl->EthStaDb_p[idx];
		item_p = (EthStaItem_t *) tmp;
		//there is one important element can not be wiped out, save it first

		memset(&item_p->ethStaInfo, 0, sizeof(eth_StaInfo_t));
		memcpy(&item_p->ethStaInfo.Addr, Addr_p, sizeof(IEEEtypes_MacAddr_t));
		item_p->ethStaInfo.pStaInfo_t = StaInfo_p;

		if (search_p) {	/*if hash table index idx already exist */
			while (search_p->nxt_ht) {
				search_p = search_p->nxt_ht;
			}
			search_p->nxt_ht = item_p;
			item_p->prv_ht = search_p;
			item_p->nxt_ht = NULL;
		} else {	/*put item to hash table idx */
			item_p->nxt_ht = item_p->prv_ht = NULL;
			vmacSta_p->EthStaCtl->EthStaDb_p[idx] = item_p;
		}

		ListPutItem(&vmacSta_p->EthStaCtl->EthStaList, tmp);
		item_p->ethStaInfo.TimeStamp = vmacSta_p->EthStaCtl->aging_time_in_minutes;

		/*-------------------------------------------------------*/
		/* Finished - give back the semaphore and return status. */
		/*-------------------------------------------------------*/
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (ADD_SUCCESS);
	} else {
		/*-------------------------------------------------------------*/
		/* There is no room in the table to add the station; give back */
		/* the semaphore and return status.                            */
		/*-------------------------------------------------------------*/
		/* Remove the least active station, and use the space for the new
		 * one */
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (TABLE_FULL_ERROR);
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

extStaDb_Status_e ethStaDb_DelSta(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, int option)
{
	extStaDb_Status_e result;
	EthStaItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p = vmac_p;
	unsigned long dbflags = 0;
	bool need_lock = !(option & STADB_NO_BLOCK);

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}

	if (!vmacSta_p->EthStaCtl->eInitialized) {
		return (NOT_INITIALIZED);
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	if (need_lock)
		SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	/*--------------------------------------------------------------*/
	/* In the table, find the station that is to be deleted; if not */
	/* found, give back the semaphore and return error status.      */
	/*--------------------------------------------------------------*/
	result = EthStaLocateAddr(vmacSta_p, Addr_p, &item_p, &idx);

	if ((result != LOCATE_SUCCESS) || !item_p) {
		if (need_lock)
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return (result);
	}
	/*----------------------------------------*/
	/* Put the element back on the free list. */
	/*----------------------------------------*/
	{
		EthStaItem_t *search_p = vmacSta_p->EthStaCtl->EthStaDb_p[idx];
		if (search_p) {
			while (memcmp(&(search_p->ethStaInfo.Addr), item_p->ethStaInfo.Addr, 6 * sizeof(IEEEtypes_Addr_t))) {
				search_p = search_p->nxt_ht;
			}
		}
		if (search_p && item_p) {
			if (search_p->prv_ht && search_p->nxt_ht) {	/*middle element */
				item_p->nxt_ht->prv_ht = item_p->prv_ht;
				item_p->prv_ht->nxt_ht = item_p->nxt_ht;
			} else {
				if (search_p->prv_ht) {	/*this is tail */
					search_p->prv_ht->nxt_ht = NULL;
				} else if (search_p->nxt_ht) {	/*this is header */
					search_p->nxt_ht->prv_ht = NULL;
					vmacSta_p->EthStaCtl->EthStaDb_p[idx] = search_p->nxt_ht;
				} else {	/*one and only */
					vmacSta_p->EthStaCtl->EthStaDb_p[idx] = NULL;
				}
			}
			item_p->nxt_ht = item_p->prv_ht = NULL;
		}
	}

	item_p->ethStaInfo.pStaInfo_t = NULL;
	memset(item_p->ethStaInfo.Addr, 0, sizeof(IEEEtypes_MacAddr_t));

	ListPutItem(&vmacSta_p->EthStaCtl->FreeEthStaList, ListRmvItem(&vmacSta_p->EthStaCtl->EthStaList, (ListItem *) item_p));
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	if (need_lock)
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (DEL_SUCCESS);
}

eth_StaInfo_t *ethStaDb_GetStaInfo(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p, int option)
{
	extStaDb_Status_e result;
	EthStaItem_t *item_p = NULL;
	UINT32 idx;
	vmacApInfo_t *vmacSta_p = vmac_p;
	bool need_lock = !(option & STADB_NO_BLOCK);
	unsigned long dbflags;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}

	if (!vmacSta_p->EthStaCtl->eInitialized) {
		return NULL;
	}

	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	if (need_lock)
		SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/* if not found, give back the semaphore and return error status.   */
	/*------------------------------------------------------------------*/
	if ((result = EthStaLocateAddr(vmacSta_p, Addr_p, &item_p, &idx)) != LOCATE_SUCCESS) {
		if (need_lock)
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
		return NULL;
	}

	/*-------------------------------------------*/
	/* Fill out the requested state information. */
	/*-------------------------------------------*/
	item_p->ethStaInfo.TimeStamp = vmacSta_p->EthStaCtl->aging_time_in_minutes;
	/*-------------------------------------------------------*/
	/* Finished - give back the semaphore and return status. */
	/*-------------------------------------------------------*/
	if (need_lock)
		SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/* For multiple BSS */
	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA)
		if ((item_p->ethStaInfo.pStaInfo_t)
		    && memcmp(&vmac_p->macBssId, &((item_p->ethStaInfo.pStaInfo_t)->Bssid), sizeof(IEEEtypes_MacAddr_t)))
			return NULL;

	return &item_p->ethStaInfo;
}

void ethStaDb_RemoveAllStns(vmacApInfo_t * vmac_p)
{
	EthStaItem_t *Curr_p, *Item_p;
	eth_StaInfo_t *ethStaInfo_p;
	vmacApInfo_t *vmacSta_p = vmac_p;
	unsigned long dbflags;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	Curr_p = (EthStaItem_t *) (vmacSta_p->EthStaCtl->EthStaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		{
			/* Item can be aged, This involves removing the item
			 * from the list and also, send message to the station
			 */
			if ((ethStaInfo_p = ethStaDb_GetStaInfo(vmac_p, &(Item_p->ethStaInfo.Addr), STADB_NO_BLOCK)) == NULL) {
				/* Station not known, do nothing */
				Curr_p = Curr_p->nxt;
				break;
			}
			ethStaDb_DelSta(vmac_p, &(Item_p->ethStaInfo.Addr), STADB_NO_BLOCK);
			Curr_p = (EthStaItem_t *) (vmacSta_p->EthStaCtl->EthStaList.head);
		}
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

UINT16 ethStaDb_list(vmacApInfo_t * vmac_p)
{
	ListItem *search;
	EthStaItem_t *search1;
	vmacApInfo_t *vmacSta_p = vmac_p;
	unsigned long dbflags;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}

	if (!vmacSta_p->EthStaCtl->eInitialized) {
		return (0);
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/
	search = vmacSta_p->EthStaCtl->EthStaList.head;
	while (search) {
		search1 = (EthStaItem_t *) search;
		{
			struct extStaDb_StaInfo_t *pStaInfo_t = search1->ethStaInfo.pStaInfo_t;
			UINT8 *p = (UINT8 *) search1->ethStaInfo.Addr;

			if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
				if ((search1->ethStaInfo.pStaInfo_t)
				    && !memcmp(&vmac_p->macBssId, &((search1->ethStaInfo.pStaInfo_t)->Bssid), sizeof(IEEEtypes_MacAddr_t))) {
					printk("eth:%02x%02x%02x%02x%02x%02x  ", p[0], p[1], p[2], p[3], p[4], p[5]);
					p = (UINT8 *) ((search1->ethStaInfo.pStaInfo_t)->Addr);
					if (pStaInfo_t)
						printk("wl:%02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
					else
						printk("\n");
				}
			}
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (1);
}

extStaDb_Status_e ethStaDb_RemoveSta(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	eth_StaInfo_t *pEthStaInfo;
	vmacApInfo_t *vmacSta_p = vmac_p;
	unsigned long dbflags;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	if ((pEthStaInfo = ethStaDb_GetStaInfo(vmac_p, Addr_p, STADB_NO_BLOCK)) == NULL) {
		/* Station not known, do nothing */
		return LOCATE_FAILURE;
	}
	ethStaDb_DelSta(vmac_p, Addr_p, STADB_NO_BLOCK);
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return (DEL_SUCCESS);
}

extStaDb_Status_e ethStaDb_RemoveStaPerWlan(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p)
{
	EthStaItem_t *Curr_p, *Item_p;
	eth_StaInfo_t *ethStaInfo_p;
	vmacApInfo_t *vmacSta_p = vmac_p;
	unsigned long dbflags;

	if (vmac_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		if (vmac_p->master)
			vmacSta_p = vmac_p->master;
	}

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	Curr_p = (EthStaItem_t *) (vmacSta_p->EthStaCtl->EthStaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		{
			/* Item can be aged, This involves removing the item
			 * from the list and also, send message to the station
			 */
			if ((ethStaInfo_p = ethStaDb_GetStaInfo(vmac_p, &(Item_p->ethStaInfo.Addr), STADB_NO_BLOCK)) == NULL) {
				/* Station not known, do nothing */
				Curr_p = Curr_p->nxt;
				break;
			}
			if (Item_p->ethStaInfo.pStaInfo_t && !memcmp(Addr_p, Item_p->ethStaInfo.pStaInfo_t->Addr, sizeof(IEEEtypes_MacAddr_t))) {
				ethStaDb_DelSta(vmac_p, &(Item_p->ethStaInfo.Addr), STADB_NO_BLOCK);
				Curr_p = (EthStaItem_t *) (vmacSta_p->EthStaCtl->EthStaList.head);
			} else
				Curr_p = Curr_p->nxt;
		}
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
	return (DEL_SUCCESS);
}

void ethStaDb_ProcessAgeTick(UINT8 * data)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;
	EthStaItem_t *Curr_p, *Item_p;
	eth_StaInfo_t *ethStaInfo_p;
	UINT32 count = 0;
	unsigned long dbflags;

	WLDBG_INFO(DBG_LEVEL_10, "ethStaDb_ProcessAgeTick \n");

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	Curr_p = (EthStaItem_t *) (vmacSta_p->EthStaCtl->EthStaList.head);
	while (Curr_p != NULL) {
		if (count++ > EXT_STA_TABLE_SIZE_RUNNING)
			break;
		Item_p = Curr_p;
		if (--Item_p->ethStaInfo.TimeStamp) {
			Curr_p = Curr_p->nxt;
		} else {
			/* Item can be aged, This involves removing the item from the list      */
			if ((ethStaInfo_p = ethStaDb_GetStaInfo(vmacSta_p, &(Item_p->ethStaInfo.Addr), STADB_NO_BLOCK)) == NULL) {
				/* Station not known, do nothing */
				SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
				return;
			}

			ethStaDb_DelSta(vmacSta_p, &(Item_p->ethStaInfo.Addr), STADB_NO_BLOCK);

			WLDBG_EXIT(DBG_LEVEL_10);
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

			return;
		}
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
}

extern int set_rptrSta_aging_time(vmacApInfo_t * vmac_p, int minutes)
{
	vmacApInfo_t *vmacSta_p;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	vmacSta_p->EthStaCtl->aging_time_in_minutes = minutes * 60 / AGING_TIMER_VALUE_IN_SECONDS;
	return minutes;
}

#ifdef MULTI_AP_SUPPORT
/*!
* get stations' mac addresses from stnid
* @param buf Pointer to station list data structure
* @return OS_SUCCESS
*         OS_FAIL      
*/
extern extStaDb_StaInfo_t *extStaDb_GetStaInfoStn(vmacApInfo_t * vmac_p, UINT8 stnid)
{
	ListItem *search;
	ExtStaInfoItem_t *Entry;
	vmacApInfo_t *vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	unsigned long dbflags;

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;
	if (!vmacSta_p->StaCtl->Initialized) {
		return NULL;
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		Entry = (ExtStaInfoItem_t *) search;

		//printk("stnid = %d, mac = %s \n", search1->StaInfo.StnId, mac_display(search1->StaInfo.Addr));

		if (Entry->StaInfo.StnId == stnid) {
			StaInfo_p = &Entry->StaInfo;

			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
			return StaInfo_p;
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return StaInfo_p;

}

extern MultiAP_4Addrr_Table_t fourAddrTable;
extern MultiAP_4Addrr_Table_t fourAddrTableSTA;

inline static UINT32 Hash4addr(UINT32 Key)
{
	unsigned int result;

	/*-------------------------------------------------------------*/
	/* Call a hash function; the current routines are experimental */
	/* and not final.                                              */
	/*-------------------------------------------------------------*/
	/* result = Jenkins32BitMix(Key); */
	result = (*Wang32BitMixFp) (Key);
	//result = Wang32BitMix(Key); 

	/*------------------------------------------------------------------*/
	/* Scale the result of the hash down to the size of the hash table. */
	/*------------------------------------------------------------------*/

	/*Try not to use floating point computations.... Rahul */

	//result = ((float)result / ULONG_MAX) * EXT_STA_TABLE_SIZE_RUNNING;
	result = result % EXT_STA_TABLE_SIZE_RUNNING;
	return (result);
}

void FourAddr_HashInit(void)
{
	int i;
	//printk("FourAddr_HashInit\n");
	memset(&fourAddrTable, 0x00, sizeof(MultiAP_4Addrr_Table_t));
	memset(&fourAddrTableSTA, 0x00, sizeof(MultiAP_4Addrr_Table_t));
	for (i = 0; i < MAX_4ADDR_TABLE_SIZE; i++) {
		fourAddrTable.entry[i].head = 1;
		fourAddrTableSTA.entry[i].head = 1;
	}
}

int FourAddr_SearchHashEntry(IEEEtypes_MacAddr_t * Addr_p, MultiAP_4Addr_Entry_t ** entry, UINT8 type)
{
	int index = 0;
	int found = 0;
	unsigned long key;

	memcpy(&key, ((IEEEtypes_Addr_t *) Addr_p + 2 * sizeof(IEEEtypes_Addr_t)), 4 * sizeof(IEEEtypes_Addr_t));

	/* do not accept keys with zero value */
	if (key == 0) {
		return -1;
	}

	index = Hash4addr(key);
	if (type == 1)
		(*entry) = &fourAddrTableSTA.entry[index];
	else
		(*entry) = &fourAddrTable.entry[index];
	//printk("index: %d , %x\n", index, (*entry));
	//printk("SA = %s, Addr_p = %s\n", mac_display((*entry)->SA), mac_display(Addr_p));
	while ((*entry)) {
		if (!memcmp((*entry)->SA, Addr_p, 6 * sizeof(IEEEtypes_Addr_t))) {
			found = 1;
			return found;
		}
		if ((*entry)->nxtEntry == NULL) {
			return 0;
		}
		(*entry) = (*entry)->nxtEntry;
	}
	return found;
}

int FourAddr_AddHashEntry(MultiAP_4Addr_Entry_t ** currentEntry, IEEEtypes_MacAddr_t * Addr2_p, IEEEtypes_MacAddr_t * Addr4_p)
{
	MultiAP_4Addr_Entry_t *nwEntry;

	if (*currentEntry == NULL) {
		return -1;
	}

	if ((*currentEntry)->nxtEntry != NULL) {
		/* This is not the last entry in the link list */
		return -1;
	}

	if ((*currentEntry)->head == 1) {
		(*currentEntry)->prvEntry = NULL;
		(*currentEntry)->nxtEntry = NULL;
		memcpy((*currentEntry)->tar, Addr2_p, sizeof(IEEEtypes_MacAddr_t));
		memcpy((*currentEntry)->SA, Addr4_p, sizeof(IEEEtypes_MacAddr_t));
		(*currentEntry)->head = 2;	// head is used
		return 0;
	} else {
		if (((*currentEntry)->nxtEntry = (MultiAP_4Addr_Entry_t *) (wl_kmalloc(sizeof(MultiAP_4Addr_Entry_t), GFP_ATOMIC))) == NULL) {
			return -1;
		}
		nwEntry = (MultiAP_4Addr_Entry_t *) (*currentEntry)->nxtEntry;
		nwEntry->head = 0;	// not head and it is a node in the list
		nwEntry->prvEntry = (MultiAP_4Addr_Entry_t *) (*currentEntry);
		nwEntry->nxtEntry = NULL;
		memcpy(&nwEntry->tar, Addr2_p, sizeof(IEEEtypes_MacAddr_t));
		memcpy(&nwEntry->SA, Addr4_p, sizeof(IEEEtypes_MacAddr_t));
		//printk("FourAddr_AddHashEntry: alloc 0x%x\n", nwEntry);
	}

	return 0;
}

int FourAddr_IfDelHashEntry(IEEEtypes_MacAddr_t * Addr_p)
{
	MultiAP_4Addr_Entry_t *entry = NULL;
	MultiAP_4Addr_Entry_t *pre_entry = NULL, *next_entry = NULL, *del_entry = NULL;
	int found = 0;

	found = FourAddr_SearchHashEntry(Addr_p, &entry, 0);

	if ((found == 1) && (entry != NULL)) {
		/* Node is the head of hash table */
		if (entry->head == 2) {
			/* if next node is null, just clear head entry */
			if (entry->nxtEntry == NULL) {
				memset(entry, 0x00, sizeof(MultiAP_4Addr_Entry_t));
				entry->head = 1;	/* head node is not used */
			} else {	/* if next node is not null, just move next node as head */
				del_entry = entry->nxtEntry;
				memcpy(entry, del_entry, sizeof(MultiAP_4Addr_Entry_t));
				entry->prvEntry = NULL;
				entry->head = 2;	/* head node is used */
				wl_kfree(del_entry);
			}
		} else if (entry->head == 0) {	/* enrty is not head node, is the node in the linked list */
			del_entry = entry;
			pre_entry = entry->prvEntry;
			next_entry = entry->nxtEntry;
			if (pre_entry != NULL) {
				pre_entry->nxtEntry = next_entry;
				if (next_entry != NULL)
					next_entry->prvEntry = pre_entry;
				wl_kfree(del_entry);
			}
		}
	}

	return 0;
}

int FourAddr_ClearHashEntry(void)
{
	MultiAP_4Addr_Entry_t *entry;
	MultiAP_4Addr_Entry_t *delEntry;
	int i;

	for (i = 0; i < MAX_4ADDR_TABLE_SIZE; i++) {
		entry = &fourAddrTable.entry[i];

		//printk("FourAddr_ClearHashEntry entry[%d] 0x%x\n", i, entry);

		while (entry) {
			if (entry->head > 0) {
				entry = entry->nxtEntry;
				continue;
			}
			delEntry = entry;
			entry = entry->nxtEntry;
			//printk("FourAddr_ClearHashEntry: Free 0x%x\n", delEntry);
			wl_kfree(delEntry);
		}
	}

	memset(&fourAddrTable, 0x00, sizeof(MultiAP_4Addrr_Table_t));
	for (i = 0; i < MAX_4ADDR_TABLE_SIZE; i++) {
		fourAddrTable.entry[i].head = 1;
	}

	return 0;
}

int FourAddr_ClearHashEntrySTA(void)
{
	MultiAP_4Addr_Entry_t *entry;
	MultiAP_4Addr_Entry_t *delEntry;
	int i;

	for (i = 0; i < MAX_4ADDR_TABLE_SIZE; i++) {
		entry = &fourAddrTableSTA.entry[i];

		//printk("FourAddr_ClearHashEntry entry[%d] 0x%x\n", i, entry);

		while (entry) {
			if (entry->head > 0) {
				entry = entry->nxtEntry;
				continue;
			}
			delEntry = entry;
			entry = entry->nxtEntry;
			//printk("FourAddr_ClearHashEntry: Free 0x%x\n", delEntry);
			wl_kfree(delEntry);
		}
	}

	memset(&fourAddrTableSTA, 0x00, sizeof(MultiAP_4Addrr_Table_t));
	for (i = 0; i < MAX_4ADDR_TABLE_SIZE; i++) {
		fourAddrTableSTA.entry[i].head = 1;
	}

	return 0;
}
#endif

extern extStaDb_StaInfo_t *extStaDb_GetVapStaInfoStn(vmacApInfo_t * vmacSta_p, UINT8 stnid)
{
	ListItem *search;
	ExtStaInfoItem_t *Entry;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	unsigned long dbflags;

	if (!vmacSta_p->StaCtl->Initialized) {
		return NULL;
	}
	/*-----------------------------------------------------------------*/
	/* Get the semaphore to gain access to the table; this may involve */
	/* a wait if the semaphore is currently held by another task.      */
	/*-----------------------------------------------------------------*/
	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);

	/*------------------------------------------------------------------*/
	/* In the table, find the station for which the state is requested; */
	/*------------------------------------------------------------------*/

	search = vmacSta_p->StaCtl->StaList.head;
	while (search) {
		Entry = (ExtStaInfoItem_t *) search;

		if (Entry->StaInfo.StnId == stnid) {
			StaInfo_p = &Entry->StaInfo;

			SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);
			return StaInfo_p;
		}
		search = search->nxt;
	}

	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	return StaInfo_p;
}
