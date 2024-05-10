/** @file ap8xLnxVer.h
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

#ifndef AP8X_VER_H_
#define AP8X_VER_H_

#define OS_SUFFIX

#ifdef SOC_W906X
#define SOC_SUFFIX  "-W906x"
#define DRV_VERSION_SUFFIX  "25.2.2082.00"
#else
#define SOC_SUFFIX	"-W8964"
#define DRV_VERSION_SUFFIX  "25.2.2082.00"
#endif

#define PLATFORM_SUFFIX

#ifdef MV_CPU_BE
#define ENDIAN_SUFFIX "-BE"
#else
#define ENDIAN_SUFFIX ""
#endif

#ifdef NO_FW_DOWNLOAD
#define FEATURE_SUFFIX "-NOFWDL"
#else
#define FEATURE_SUFFIX
#endif

#ifdef EEPROM_REGION_PWRTABLE_SUPPORT
#define EEPROM_PWR_SUFFIX "-E_PWR"
#else
#define EEPROM_PWR_SUFFIX ""
#endif

#define MOD_NAME "ap8x"
#define DRV_NAME_WDS  "%swds%1d"
#define DRV_NAME_CLIENT "sta"

#ifdef ENABLE_MONIF
#define DEV_NAME_MON_INTF "mon"
#endif

#ifdef WIFI_DATA_OFFLOAD
#define DOL_VER "v1.0.28-20200424"
#define DOL_SUFFIX "-dol-" DOL_VER
#else
#define DOL_SUFFIX ""
#endif

#define DRV_VERSION   DRV_VERSION_SUFFIX ENDIAN_SUFFIX SOC_SUFFIX OS_SUFFIX PLATFORM_SUFFIX FEATURE_SUFFIX EEPROM_PWR_SUFFIX DOL_SUFFIX

#endif /* AP8X_VER_H_ */
