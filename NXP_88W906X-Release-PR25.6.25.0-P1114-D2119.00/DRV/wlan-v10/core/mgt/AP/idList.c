/** @file idList.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2003-2020 NXP
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

/*!
 * \file    idList.c
 * \brief   station id and 802.11 aid management
 */

/*=============================================================================
 *                               INCLUDE FILES
 *=============================================================================
 */

#include "wltypes.h"
#include "List.h"
#include "osif.h"
#include "buildModes.h"
#include "idList.h"
#include "ap8xLnxIntf.h"
UINT32 AssocStationsCnt = 0;
/*=============================================================================
 *                                DEFINITIONS
 *=============================================================================
*/

/*=============================================================================
 *                         IMPORTED PUBLIC VARIABLES
 *=============================================================================
 */
/*=============================================================================
 *                          MODULE LEVEL VARIABLES
 *=============================================================================
 */

extern void ListPutItemFILO(List * me, ListItem * Item);
/*============================================================================= 
 *                   PRIVATE PROCEDURES (ANSI Prototypes) 
 *=============================================================================
 */

/*============================================================================= 
 *                         CODED PROCEDURES 
 *=============================================================================
 */

/*
 *Function Name:InitAidList
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */
WL_STATUS InitAidList(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	UINT32 i;
	UINT16 bgn_aid;
	if (wlpptr->wlpd_p->AidList == NULL) {
		ListInit(&wlpptr->wlpd_p->FreeAIDList);
		ListInit(&wlpptr->wlpd_p->AIDList);
		wlpptr->wlpd_p->AidList = wl_kmalloc_autogfp((sta_num + 1) * sizeof(IdListElem_t));
		if (wlpptr->wlpd_p->AidList == NULL) {
			return (OS_FAIL);
		}
		memset(wlpptr->wlpd_p->AidList, 0, (sta_num + 1) * sizeof(IdListElem_t));
		bgn_aid = (bss_num < 8) ? (8 - 1) : (bss_num - 1);
		for (i = 0; i < sta_num; i++) {
			wlpptr->wlpd_p->AidList[i].nxt = NULL;
			wlpptr->wlpd_p->AidList[i].prv = NULL;
#ifdef SOC_W906X
			/* 
			   mbssid. AID 1~31(max support nontransmittted BSSIDs) are reserved for 
			   broadcast/multicast of each non-txed BSSIDs
			   802.11-2006 pp.794 
			 */
			wlpptr->wlpd_p->AidList[i].Id = (sta_num + bgn_aid - i);
#else
			wlpptr->wlpd_p->AidList[i].Id = sta_num - i;

#endif
			ListPutItemFILO(&wlpptr->wlpd_p->FreeAIDList, (ListItem *) (wlpptr->wlpd_p->AidList + i));
		}
	}
	return (OS_SUCCESS);
}

/*
 *Function Name:AssignAid
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */
UINT32 AssignAid(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	ListItem *tmp;
	IdListElem_t *tmp1;
	unsigned long listflags;
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	tmp = ListGetItem(&wlpptr->wlpd_p->FreeAIDList);
	if (tmp) {
		tmp1 = (IdListElem_t *) tmp;
		ListPutItemFILO(&wlpptr->wlpd_p->AIDList, tmp);
		AssocStationsCnt++;
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
		return tmp1->Id;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	return 0;		/* List is empty */
}

/*
 *Function Name:FreeAid
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */

void FreeAid(vmacApInfo_t * vmacSta_p, UINT32 Aid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	ListItem *search;
	IdListElem_t *search1;
	unsigned long listflags;
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	search = wlpptr->wlpd_p->AIDList.head;
	while (search) {
		search1 = (IdListElem_t *) search;
		if ((search1->Id == Aid)) {
			ListPutItemFILO(&wlpptr->wlpd_p->FreeAIDList, ListRmvItem(&wlpptr->wlpd_p->AIDList, search));
			AssocStationsCnt--;
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
			return;
		}
		search = search->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
}

Status_e ResetAid(vmacApInfo_t * vmacSta_p, UINT16 StnId, UINT16 Aid)
{
	return FAIL;
}

/*
 *Function Name:InitStnId
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */

WL_STATUS InitStnIdList(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	UINT32 i;
	if (wlpptr->wlpd_p->StnIdList == NULL) {
		ListInit(&wlpptr->wlpd_p->FreeStaIdList);
		ListInit(&wlpptr->wlpd_p->StaIdList);
		wlpptr->wlpd_p->StnIdList = wl_kmalloc_autogfp((sta_num + 1) * sizeof(IdListElem_t));
		if (wlpptr->wlpd_p->StnIdList == NULL)
			return (OS_FAIL);
		memset(wlpptr->wlpd_p->StnIdList, 0, (sta_num + 1) * sizeof(IdListElem_t));
#ifdef SOC_W906X
		for (i = 1; i <= sta_num; i++)
#else
		for (i = 0; i < sta_num; i++)
#endif
		{
			wlpptr->wlpd_p->StnIdList[i].nxt = NULL;
			wlpptr->wlpd_p->StnIdList[i].prv = NULL;
			wlpptr->wlpd_p->StnIdList[i].Id = sta_num - i;
			ListPutItemFILO(&wlpptr->wlpd_p->FreeStaIdList, (ListItem *) (wlpptr->wlpd_p->StnIdList + i));
		}
	}
	return (OS_SUCCESS);
}

void StnIdListCleanup(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	if (wlpptr->wlpd_p->StnIdList) {
		wl_kfree(wlpptr->wlpd_p->StnIdList);
		wlpptr->wlpd_p->StnIdList = 0;
	}
	if (wlpptr->wlpd_p->AidList) {
		wl_kfree(wlpptr->wlpd_p->AidList);
		wlpptr->wlpd_p->AidList = 0;
	}
}

/*
 *Function Name:AssignStnId
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */

UINT32 AssignStnId(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	ListItem *tmp;
	IdListElem_t *tmp1;
	unsigned long listflags;
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	tmp = ListGetItem(&wlpptr->wlpd_p->FreeStaIdList);
	if (tmp) {
		tmp1 = (IdListElem_t *) tmp;
		ListPutItemFILO(&wlpptr->wlpd_p->StaIdList, tmp);
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
		return tmp1->Id;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
#ifdef SOC_W906X
	return sta_num;		/* List is empty */
#else
	return 0;		/* List is empty */
#endif
}

/*
 *Function Name:FreeStnId
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */

int FreeStnId_newdp(vmacApInfo_t * vmacSta_p, UINT32 StnId)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	ListItem *search;
	IdListElem_t *search1;
	unsigned long listflags;
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	search = wlpptr->wlpd_p->StaIdList.head;
	while (search) {
		search1 = (IdListElem_t *) search;
		if ((search1->Id == StnId)) {
			ListPutItem(&wlpptr->wlpd_p->FreeStaIdList, ListRmvItem(&wlpptr->wlpd_p->StaIdList, search));
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
			return 1;
		}
		search = search->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	return 0;
}

void FreeStnId(vmacApInfo_t * vmacSta_p, UINT32 StnId)
{
#ifdef NEW_DP
	return;
#else
	FreeStnId_newdp(vmacApInfo_t * vmacSta_p, UINT32 StnId);
#endif
}

void Display_StnIDs(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	ListItem *search;
	unsigned long listflags;
	int free = 0;
	int used = 0;
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	search = wlpptr->wlpd_p->StaIdList.head;
	while (search) {
		search = search->nxt;
		used++;
	}
	search = wlpptr->wlpd_p->FreeStaIdList.head;
	while (search) {
		search = search->nxt;
		free++;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	printk("\nid %d used and %d left\n", used, free);
	free = 0;
	used = 0;
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	search = wlpptr->wlpd_p->AIDList.head;
	while (search) {
		search = search->nxt;
		used++;
	}
	search = wlpptr->wlpd_p->FreeAIDList.head;
	while (search) {
		search = search->nxt;
		free++;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.ReqidListLock, listflags);
	printk("\naid %d used and %d left\n", used, free);
}
