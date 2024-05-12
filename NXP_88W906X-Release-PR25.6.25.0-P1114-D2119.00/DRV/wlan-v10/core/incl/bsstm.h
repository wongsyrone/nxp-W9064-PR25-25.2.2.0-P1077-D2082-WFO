/** @file bsstm.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2017-2020 NXP
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
 * \file  bsstm.h
 * \brief
 */

#if !defined(_BSSTM_H_)
#define _BSSTM_H_

#if defined(AP_STEERING_SUPPORT)  && defined(IEEE80211K)

extern BOOLEAN bsstm_send_request(struct net_device *netdev, UINT8 * destaddr, struct IEEEtypes_BSS_TM_Request_t *btmreq_p);
extern BOOLEAN bsstm_send_response(vmacApInfo_t * vmacSta_p, void *StaMgmtMsg_p);
extern void bsstm_disassoc_timer_set(UINT32 disassoc_time);
extern void bsstm_disassoc_timer_del(void);
extern void bsstm_AssocDenied(UINT32 disassoc_time);

#endif				//AP_STEERING_SUPPORT && IEEE80211K
#endif				/* _BSSTM_H_ */
