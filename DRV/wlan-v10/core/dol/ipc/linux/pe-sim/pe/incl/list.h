/** @file list.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#ifndef __LIST_H__
#define __LIST_H__

struct list_item {
	struct list_item *nxt;
	struct list_item *prv;
};

struct list {
	struct list_item *head;
	struct list_item *tail;
	unsigned int cnt;
};

static inline void
list_init(struct list *me)
{
	me->head = NULL;
	me->tail = NULL;
	me->cnt = 0;
}

/* there is no protection for these functions due to super loop */

static inline struct list_item *
list_peek_item(struct list *me)
{
	struct list_item *item;

	if (!me->cnt)
		return NULL;

	item = me->tail;

	return item;
}

static inline struct list_item *
list_get_item(struct list *me)
{
	struct list_item *item;

	if (!me)
		return NULL;

	if (!me->cnt)
		return NULL;

	item = me->tail;

	if (me->tail->prv) {
		me->tail = me->tail->prv;
		me->tail->nxt = NULL;
	} else
		me->head = me->tail = NULL;

	item->nxt = item->prv = NULL;
	me->cnt--;

	return item;
}

static inline void
list_put_item(struct list *me, struct list_item *item)
{
	if (item == NULL)
		return;

	item->nxt = me->head;
	item->prv = NULL;

	if (me->head)
		me->head->prv = item;
	else
		me->tail = item;
	me->head = item;
	me->cnt++;

	return;
}

static inline struct list_item *
list_remove_item(struct list *me, struct list_item *item)
{
	if (item == NULL)
		return NULL;
	if (me->cnt == 0)
		return NULL;

	if (item->prv && item->nxt) {	/*not head neither tail */
		item->prv->nxt = item->nxt;
		item->nxt->prv = item->prv;
	} else {
		if (item->prv) {	/*this is tail */
			item->prv->nxt = NULL;
			me->tail = item->prv;
		} else if (item->nxt) {	/*this is head */
			item->nxt->prv = NULL;
			me->head = item->nxt;
		} else {	/*only one item in the list */
			//Assuming there is only 1 item in the list, but we need to check if this is the item in the list
			if ((item == me->tail) && (item == me->head)) {
				me->head = me->tail = NULL;
			} else {
				//We're trying to remove something not in the list, skip here.
				return NULL;
			}
		}
	}

	item->nxt = NULL;
	item->prv = NULL;
	me->cnt--;

	return item;
}

static inline struct list_item *
list_search_item(struct list *me, struct list_item *item)
{
	struct list_item *curr_item = NULL;

	if (item == NULL)
		return NULL;
	if (me->cnt == 0)
		return NULL;

	curr_item = list_peek_item(me);

	while (curr_item != NULL) {
		if (curr_item == item) {
			break;
		} else {
			curr_item = curr_item->prv;
		}
	}

	return curr_item;
}

#endif /* __LIST_H__ */
