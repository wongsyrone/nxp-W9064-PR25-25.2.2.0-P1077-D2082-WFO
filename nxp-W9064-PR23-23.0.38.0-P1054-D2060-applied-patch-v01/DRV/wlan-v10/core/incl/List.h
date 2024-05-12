/** @file List.h
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

#ifndef list_h
#define list_h

typedef struct ListItem {
	struct ListItem *nxt;
	struct ListItem *prv;
} ListItem;

typedef struct List {
	ListItem *head;
	ListItem *tail;
	unsigned int cnt;
} List;

typedef struct MU_Set_List {
	ListItem *head;
	ListItem *tail;
	unsigned int cnt;
	unsigned int total_sta;	//total stations in all MU sets combined
} MU_Set_List;

typedef struct MU_Sta_List {
	ListItem *head;
	ListItem *tail;
	unsigned int cnt;	//total MU capable station in list
	unsigned int taken_musta_cnt;	//cnt of MU sta in list that is already in a MU set
} MU_Sta_List;

void MUSetListInit(MU_Set_List * me);
void MUStaListInit(MU_Sta_List * me);

void ListInit(List * me);
ListItem *ListGetItem(List * me);
void ListPutItem(List * me, ListItem * Item);
ListItem *ListDelItem(List * me, ListItem * Item);
ListItem *ListRmvItem(List * me, ListItem * Item);

#endif
