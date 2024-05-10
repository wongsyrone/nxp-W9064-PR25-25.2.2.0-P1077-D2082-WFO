/** @file shal_list.h
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
 * @brief SMAC common list APIs (shared between SFW and PFW).
 */

#ifndef _SHAL_LIST_H_
#define _SHAL_LIST_H_

#ifndef __KERNEL__
/**
 * @brief Macro to iterate over a list using a user specified loop cursor.
 *
 * @param cur   the variable used for cursor, representing the current list node.
 * @param list  the head for your list.
 */
#define list_for_each(cur, list) \
for ((cur) = (list)->next; (cur) != (list); (cur) = (cur)->next)

#endif /* #ifndef __KERNEL__ */

/**
 * @brief An element in a doubly-linked circular list.
 *
 *  A list is a doubly-linked circular list.
 *  A list is identified by a dummy list element, which is an empty list element.
 *  It never carries any information other than list bookkeeping data, and it is
 *  always linked as an element within the list.
 *  Dummy element's next points to the head of the list and its prev points to the
 *  tail.\n
 *  Therefore, an empty list always contains one element, the dummy element, whose
 *  prev and next pointers loop back to itself.

 *  To enable listing a data structure within a list, the easiest solution is
 *  letting the first field of that data structure be a LIST_ELEM_st instance,
 *  i.e.:
 *  @code
 *  struct Sample
 *  {
 *     LIST_ELEM_st link;
 *     int someData;
 *     // more data ...
 *  };
 *  @endcode
 *
 *  @see LIST_init() for general details about lists.
 */
typedef struct LIST_ELEM_st {
	struct LIST_ELEM_st *next;
	struct LIST_ELEM_st *prev;
} LIST_ELEM_st;

/**
 *  @brief Initializes a list, as an empty list.
 *  @param list The list descriptor, i.e. the fake list element that identifies a given list.
 *
 *  @note If called on an already-initialized list, the list is emptied without
 *        performing any clean-up action on any existing element.
 */
static SHAL_INLINE void
LIST_init(LIST_ELEM_st * list)
{
	list->next = list;
	list->prev = list;
}

/**
 *  @brief Initializes an element, as an element not yet bound within a list.
 *  @param elem The element to Initialize.
 */
static SHAL_INLINE void
LIST_elemInit(LIST_ELEM_st * elem)
{
	elem->next = 0;
	elem->prev = 0;
}

/**
 *  @brief  Checks if a list is empty.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @return TRUE is the list is empty else FALSE.
 */
static SHAL_INLINE BOOL
LIST_isEmpty(LIST_ELEM_st * list)
{
	return (list->next == list);
}

/**
 *  @brief  Checks if a list is not empty.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @return TRUE is the list is not empty else FALSE.
 */
static SHAL_INLINE BOOL
LIST_isNotEmpty(LIST_ELEM_st * list)
{
	return !LIST_isEmpty(list);
}

/**
 *  @brief  Inserts a new element in a list before a given existing element.
 *  @param  list    The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem    The new element is placed before this element.
 *  @param  newElem New element to insert in the list.
 */
static SHAL_INLINE void
LIST_insertBefore(LIST_ELEM_st * list, LIST_ELEM_st * elem,
		  LIST_ELEM_st * newElem)
{
	SHAL_ASSERT(newElem != list);

	(void)list;

	(elem->prev)->next = newElem;
	newElem->next = elem;
	newElem->prev = elem->prev;
	elem->prev = newElem;
}

/**
 *  @brief  Inserts a new element in a list after a given existing element.
 *  @param  list    The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem    The new element is placed after this element.
 *  @param  newElem New element to insert in the list.
 */
static SHAL_INLINE void
LIST_insertAfter(LIST_ELEM_st * list, LIST_ELEM_st * elem,
		 LIST_ELEM_st * newElem)
{
	SHAL_ASSERT(newElem != list);

	(void)list;

	(elem->next)->prev = newElem;
	newElem->next = elem->next;
	newElem->prev = elem;
	elem->next = newElem;
}

/**
 *  @brief  Adds an element at the head of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem New element to insert in the list
 */
static SHAL_INLINE void
LIST_addHead(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	LIST_insertAfter(list, list, elem);
}

/**
 *  @brief  Adds an element in a list at the tail of that list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem New element to insert in the list.
 */
static SHAL_INLINE void
LIST_addTail(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	LIST_insertBefore(list, list, elem);
}

/**
 *  @brief  Returns the first element of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @return The first element of the list.
 *
 *  @note This function does not remove the first element from the list.
 *        @ref LIST_getFirst() does remove and return the first element of a list.
 */
static SHAL_INLINE LIST_ELEM_st *
LIST_peekFirst(LIST_ELEM_st * list)
{
	return (list->next);
}

/**
 *  @brief  Returns the element next to a given element of a list.
 *  @param  elem The element for which the next element is requested.
 *  @return The element next to the given element.
 */
static SHAL_INLINE LIST_ELEM_st *
LIST_peekNext(LIST_ELEM_st * elem)
{
	return (elem->next);
}

/**
 *  @brief  Returns the last element of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @return The last element of the list.
 *
 */
static SHAL_INLINE LIST_ELEM_st *
LIST_peekLast(LIST_ELEM_st * list)
{
	return (list->prev);
}

#define DBG_LIST_TRACE          TRUE
#if defined(DBG_LIST_TRACE)
typedef struct LISTTRACE_st {
//DW0
	U32 info;
//DW1
	U32 list;
//DW2
	U32 elem;
} LISTTRACE_st;
#define DBG_MAX_LISTTRACE_SIZE 32
extern LISTTRACE_st gDbg_listTrace[DBG_MAX_LISTTRACE_SIZE];
extern U8 gDbg_listTrace_index;

#endif

/**
 *  @brief  Removes an element from a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem The element to remove.
 */
#if defined(BUILD_PFW)
extern U32 pfw_list_err_cnt[16];
#endif

static SHAL_INLINE void
LIST_remove(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	SHAL_ASSERT(elem != list);

	(void)list;

	if ((elem->next == 0) || (elem->prev == 0)) {
#if defined(BUILD_PFW)
		pfw_list_err_cnt[0]++;
#endif
		return;
	}
	(elem->prev)->next = elem->next;
	(elem->next)->prev = elem->prev;

	elem->next = 0;		//to indicate this is not linked yet
	elem->prev = 0;
}

/**
 *  @brief  Moves an element (linked to a list) into a destination list.
 *  @param  dstList The list descriptor, i.e. the fake list element that identifies the destination list.
 *  @param  elem The element to move.
 *
 *  @note  Compared to doing List_remove + LIST_addTail, this API will not
 *  temporarly unlink the element from its original list. Unlinking the element
 *  could result in concurrency problems (e.g. multiple parties seeing the element
 *  as unlinked so trying to do operations on it).
 */
static SHAL_INLINE void
LIST_move(LIST_ELEM_st * dstList, LIST_ELEM_st * elem)
{
	SHAL_ASSERT(elem != dstList);
	SHAL_ASSERT(elem != 0);

	if (elem->next)
		(elem->prev)->next = elem->next;
	if (elem->prev)
		(elem->next)->prev = elem->prev;

	LIST_addTail(dstList, elem);
}

/**
 *  @brief  Removes and returns the first element of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @return The first element of the list.
 */
static SHAL_INLINE LIST_ELEM_st *
LIST_getFirst(LIST_ELEM_st * list)
{
	LIST_ELEM_st *elem;

	elem = LIST_peekFirst(list);
	LIST_remove(list, elem);

	return elem;
}

/**
 *  @brief  Checks if a list node is linked in a list or not.
 *  @param  elem The element to check.
 *  @return TRUE if the element is linked, FALSE otherwise.
 */
static SHAL_INLINE BOOL
LIST_isElemLinked(LIST_ELEM_st * elem)
{
	return (elem->next != 0);
}

/**
 *  @brief  Checks if elem correspond to the first element of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem The element to check.
 *  @return TRUE if elem is the first element of the list, FALSE otherwise.
 */
static SHAL_INLINE BOOL
LIST_isFirst(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	SHAL_ASSERT(elem != list);

	(void)list;

	return (elem->prev == list);
}

/**
 *  @brief  Checks if elem correspond to the last element of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem The element to check.
 *  @return TRUE if elem is the last element of the list, FALSE otherwise.
 */
static SHAL_INLINE BOOL
LIST_isLast(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	SHAL_ASSERT(elem != list);

	(void)list;

	return (elem->next == list);
}

/**
 *  @brief  Checks if elem correspond to the end of a list.
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem The element to check.
 *  @return TRUE if elem corresponds to the end of the list, FALSE otherwise.
 *
 *  @note This function is build to be used as the end condition for a for() loop
 *  i.e.:
 *  @code
 *  for (elem = (LIST_ELEM_st *)LIST_peekFirst(list);
 *        !LIST_isEnd(list, elem);
 *         elem = elem->next)
 *  @endcode
 */
static SHAL_INLINE BOOL
LIST_isEnd(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	return (elem == list);
}

/**
 * @brief Checks if elem is linked in a list.
 *
 *  @param  list The list descriptor, i.e. the fake list element that identifies a given list.
 *  @param  elem The element to check.
 *  @return TRUE if elem is linked in the list, FALSE otherwise.
 *
 */
static SHAL_INLINE BOOL
List_Find(LIST_ELEM_st * list, LIST_ELEM_st * elem)
{
	LIST_ELEM_st *cur;

	list_for_each(cur, list) {
		if (cur == elem) {
			return TRUE;
		}
	}

	return FALSE;
}

/**
 *  @brief  Appends a list to another list
 *  @param  destList The descriptor of the list on which a list is appended
 *  @param  list     The descriptor of list which is appended
 */
static SHAL_INLINE void
LIST_appendList(LIST_ELEM_st * destList, LIST_ELEM_st * list)
{
	LIST_ELEM_st *first;
	LIST_ELEM_st *last;
	LIST_ELEM_st *destLast;

	if (LIST_isEmpty(list)) {
		return;
	}

	first = LIST_peekFirst(list);
	last = LIST_peekLast(list);
	destLast = LIST_peekLast(destList);

	first->prev = destLast;
	last->next = destList;

	destLast->next = first;
	destList->prev = last;

	LIST_init(list);
}

/** return to check whether a list is empty, for debug purpose **/
static SHAL_INLINE BOOL
LIST_appendListCheck(LIST_ELEM_st * destList, LIST_ELEM_st * list)
{
	LIST_ELEM_st *first;
	LIST_ELEM_st *last;
	LIST_ELEM_st *destLast;

	if (LIST_isEmpty(list)) {
		return 0;
	}

	first = LIST_peekFirst(list);
	last = LIST_peekLast(list);
	destLast = LIST_peekLast(destList);

	first->prev = destLast;
	last->next = destList;

	destLast->next = first;
	destList->prev = last;

	LIST_init(list);
	return 1;
}

#endif // _SHAL_LIST_H_
