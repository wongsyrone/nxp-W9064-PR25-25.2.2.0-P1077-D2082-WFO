/** @file ap8xLnxAtf.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
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

#ifndef __AP8XLNXATF_H__
#define __AP8XLNXATF_H__

#include "wltypes.h"

enum atf_cfg_params {
	ATF_PARAM_VI,
	ATF_PARAM_BE,
	ATF_PARAM_BK,
	ATF_PARAM_AIRTIME,
};

enum atf_debug {
	ATF_DEBUG_TRACES,
	ATF_DEBUG_STATS,
};

extern int atf_debug_enable(struct net_device *netdev, u8 debug_feature,
			    u8 enable);
extern void atf_irq_task_handler(struct work_struct *work);

#endif /* __AP8XLNXATF_H__ */
