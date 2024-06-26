/** @file ap8xLnxFwdl.h
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
#ifndef AP8X_FWDL_H_
#define AP8X_FWDL_H_

#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/version.h>
#include "ap8xLnxIntf.h"

extern int wlFwDownload(struct net_device *);
extern void wlReleaseFw(struct net_device *);
extern int wlPrepareFwFile(struct net_device *);
#ifdef FS_CAL_FILE_SUPPORT
extern int wlDownloadMFGFile(struct net_device *);
extern int wlFreeMFGFileBuffer(struct net_device *);
#endif
#endif				/* AP8X_FWDL_H_ */
