/** @file mhsm.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2007-2020 NXP
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
#ifndef MHSM_
#define MHSM_

#include "wltypes.h"

/******************************************************************/
/*!
 *  \internal
 *  \defgroup marvell_hsm NXP HSM implementation
 *
 *  Ths group covers functions used for the NXP Hierarchical
 *  MhsmState_t Machine (HSM).  The MhsmState_t structures and HSM are
 *  separated to allowed multiple instances of an HSM to use the
 *  same state transition structures.
 */
/******************************************************************/
/*!
 *  \internal 
 *  \ingroup marvell_hsm
 *  \file   mhsm.h
 *  \brief  Internal API for the NXP HSM
 *
 *  This file contains the APIs and structures required for the 
 *  NXP HSM.
 *
 *******************************************************************/
#define MHSM_ENTER 0xffffffff
#define MHSM_EXIT  0xfffffffe
#define MhsmInState(sm_, state) (((Mhsm_t *)&sm_)->pCurrent == &sm_.state)

#define MhsmInSyncState(sm_, state) (((Mhsm_t *)&sm_)->pCurrent == &sm_.pStates->state)

typedef struct Mhsm_ Mhsm_t;
typedef UINT32 Event_t;

/*! The event to be passed to the NXP HSM */
typedef struct MhsmEvent_ {
	/*! The event to be processed */
	Event_t event;

	/*! Any addition data needed by the event processor */
	void *pBody;
	unsigned char *info;
	unsigned char *devinfo;
} MhsmEvent_t;

typedef MhsmEvent_t const *(*MhsmFcnPtr) (Mhsm_t * pHsm, MhsmEvent_t * pEvent);

/*!  The Structure for NXP HSM States */
typedef struct MhsmState_ {
	/*! The depth of this state from the top */
	UINT32 depth;

	/*! The parent of this state */
	struct MhsmState_ *pSuper;

	/*! The event handler for the state */
	MhsmFcnPtr pProcessEventFcn;

} MhsmState_t;

struct Mhsm_ {
	/*! The current state in this NXP HSM */
	MhsmState_t *pCurrent;
};

/******************************************************************/
/*!
 *  \internal 
 *  \ingroup marvell_hsm
 *
 *  \brief Initializes an HSM
 *
 *  \param[in] pHsm       Pointer to the HSM to intialize.
 *  \param[in] pStart     Pointer to the Start state of the HSM.
 *
 *  This function intializes an instance of an HSM.  It sets the HSM
 *  to enter the Start state.
 *
 ******************************************************************/
extern void mhsm_initialize(Mhsm_t * pHsm, MhsmState_t * pStart);

/******************************************************************/
/*!
 *  \internal 
 *  \ingroup marvell_hsm
 *
 *  \brief Adds a state to an existing HSM
 *
 *  \param[in] pState     Pointer to the HSM state to add.
 *  \param[in] pSuper     Pointer to the new states super state.
 *  \param[in] pFcn       Function pointer to the event handler.
 *
 ******************************************************************/
extern void mhsm_add(MhsmState_t * pState, MhsmState_t * pSuper, MhsmFcnPtr pFcn);

/******************************************************************/
/*!
 *  \internal 
 *  \ingroup marvell_hsm
 *
 *  \brief Process an event in the HSM
 *
 *  \param[in] pHsm       Pointer to the HSM to handle the event.
 *  \param[in] pEvent     Pointer to the MSM event.
 *
 ******************************************************************/
extern void mhsm_send_event(Mhsm_t * pHsm, MhsmEvent_t * pEvent);

/******************************************************************/
/*!
 *  \internal 
 *  \ingroup marvell_hsm
 *
 *  \brief Transition the HSM from the current state to the provided
 *         destination state.
 *
 *  \param[in] pHsm       Pointer to the HSM to handle the transition.
 *  \param[in] pDest      Pointer to destination state.
 *
 ******************************************************************/
extern void mhsm_transition(Mhsm_t * pHsm, MhsmState_t * pDest);

#endif
