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

#include "wl_mib.h"
#include "ap8xLnxApi.h"
#include <linux/netdevice.h>

#define ATF_RATE_M_Hz       1000

typedef enum atf_mode_e {
	ATF_MODE0_DISABLED = 0,
	ATF_MODE1_AUTO_SIMPLE,
	ATF_MODE2_REVERSED,
	ATF_MODE3_CONFIGURED,
	ATF_MODE4_ADVANCED,
	ATF_MODE_MAX
} atf_mode_t;

void atf_print_usage(void);
void atf_enable(struct net_device *netdev, MIB_802DOT11 * mib, char *param2);
void atf_config_set(struct net_device *netdev, MIB_802DOT11 * mib, char *param2,
		    char *param3, char *param4, char *param5, char *param6, char *param7, char *param8);
void atf_config_reset(struct net_device *netdev, MIB_802DOT11 * mib);
void atf_get_fw_cfg_dump_cur(struct net_device *netdev);
void atf_dump_all_info(struct net_device *netdev, MIB_802DOT11 * mib);
void atf_check_setting(struct net_device *netdev, IEEEtypes_MacAddr_t * macaddr, u32 staidx);
#endif				/* __AP8XLNXATF_H__ */
