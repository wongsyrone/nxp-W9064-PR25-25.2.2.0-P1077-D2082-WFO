/** @file shal_cpu.h
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
#ifndef __CPU_H__
#define __CPU_H__
#define KBYTE (1024)

#define CR7_ITCM_BASE   (0)
#define CPU1_ITCM_BASE  CR7_ITCM_BASE
#define CR7_ITCM_SIZE   (32 * KBYTE)
#define CPU1_ITCM_SIZE  CR7_ITCM_SIZE
#define CR7_ITCM_TOP    (CPU1_ITCM_BASE + CPU1_ITCM_SIZE)
#define CR7_DTCM_BASE   (0x8000)
#define CPU1_DTCM_BASE   CR7_DTCM_BASE
#define CR7_DTCM_SIZE   (32 * KBYTE)
#define CPU1_DTCM_SIZE  CR7_DTCM_SIZE
#define CR7_DTCM_TOP    (CPU1_DTCM_BASE + CPU1_DTCM_SIZE)
#define CR7_IRAM_BASE   (0x100000)
#define CPU1_IRAM_BASE   CR7_IRAM_BASE
#define CR7_IRAM_SIZE   (768 * KBYTE)
#define CPU1_IRAM_SIZE  CR7_IRAM_SIZE
#define CR7_ROM_OCCUPY  (0x900)
#define CR7_IRAM_TOP    (CPU1_IRAM_BASE + CPU1_IRAM_SIZE)

#define CA7_IRAM_BASE       (0)
#define CA7_IRAM_SIZE_SC5   (256 * KBYTE)
#define CA7_IRAM_SIZE_SCBT  (128 * KBYTE)
#define CA7_IRAM_TOP_SC5    (CA7_IRAM_BASE + CA7_IRAM_SIZE_SC5)
#define CA7_IRAM_TOP_SCBT   (CA7_IRAM_BASE + CA7_IRAM_SIZE_SCBT)

#define CM3_ICODE_BASE      (0)
#define CM3_ICODE_SIZE      (16 * KBYTE)
#define CM3_ICODE_SIZE_A0_2 (20 * KBYTE)
#define CM3_ICODE_SIZE_A0_3 (20 * KBYTE)

#define CM3_DCODE_BASE      (CM3_ICODE_BASE + CM3_ICODE_SIZE)
#define CM3_DCODE_BASE_A0_2 (CM3_ICODE_BASE + CM3_ICODE_SIZE_A0_2)
#define CM3_DCODE_BASE_A0_3 (CM3_ICODE_BASE + CM3_ICODE_SIZE_A0_3)
#define CM3_DCODE_SIZE      (16 * KBYTE)
#define CM3_DCODE_SIZE_6    (28 * KBYTE)
#define CM3_DCODE_SIZE_A0_2 (20 * KBYTE)
#define CM3_DCODE_SIZE_A0_3 (20 * KBYTE)

#define DMEM_BASE                      (0x20000000)
#define DMEM_SIZE_SC5_SCBT_A0          (1168 * KBYTE)
#define DMEM_SIZE_SCBT_Z0              (1088 * KBYTE)
#define DMEM_SIZE_SC5_Z0_Z1            (896 * KBYTE)
#define DMEM_TOP_SC5_SCBT_A0           (DMEM_BASE + DMEM_SIZE_SC5_SCBT_A0)
#define DMEM_TOP_SCBT_Z0               (DMEM_BASE + DMEM_SIZE_SCBT_Z0)
#define DMEM_TOP_SC5_Z0_Z1             (DMEM_BASE + DMEM_SIZE_SC5_Z0_Z1)

#define DEBUG_RECORD_SIZE              (2 * KBYTE)
#define DEBUG_RECORD_BASE_SC5_SCBT_A0  (DMEM_TOP_SC5_SCBT_A0 - DEBUG_RECORD_SIZE)
#define DEBUG_RECORD_BASE_SCBT_Z0      (DMEM_TOP_SCBT_Z0 - DEBUG_RECORD_SIZE)
#define DEBUG_RECORD_BASE_SC5_Z0_Z1    (DMEM_TOP_SC5_Z0_Z1 - DEBUG_RECORD_SIZE)

#define DFS_BUF_SIZE                   (6 * KBYTE)
#define DFS1_BUF_SIZE                  (0x810)
#define DFS2_BUF_SIZE                  (0xFF0)
#define DFS_BUF_BASE_SC5_SCBT_A0       (DEBUG_RECORD_BASE_SC5_SCBT_A0 - DFS_BUF_SIZE)
#define DFS_BUF_BASE_SCBT_Z0           (DEBUG_RECORD_BASE_SCBT_Z0 - DFS_BUF_SIZE)
#define DFS_BUF_BASE_SC5_Z0_Z1         (DEBUG_RECORD_BASE_SC5_Z0_Z1 - DFS_BUF_SIZE)

#define RECV_CMD_BUF_SIZE              (4096+24)
#define SSU_RECORD_SIZE                (2304)
#define EVENT_RECORD_SIZE              (328)
#define FIPS_SIZE                      (656)
#define ATF_SIZE                       (92200)
#define TXINFO_SIZE                    (0x400)

#define PFW_DMEM_SIZE                  (RECV_CMD_BUF_SIZE + SSU_RECORD_SIZE + EVENT_RECORD_SIZE + FIPS_SIZE + ATF_SIZE)
#define PFW_DMEM_BASE_SC5_SCBT_A0      (DFS_BUF_BASE_SC5_SCBT_A0 - PFW_DMEM_SIZE)
#define PFW_DMEM_BASE_SCBT_Z0          (DFS_BUF_BASE_SCBT_Z0 - PFW_DMEM_SIZE)
#define PFW_DMEM_BASE_SC5_Z0_Z1        (DFS_BUF_BASE_SC5_Z0_Z1 - PFW_DMEM_SIZE)

#define CAL_DATA_CONF_FILE_SIZE        (6 * KBYTE)
#define CAL_DATA_CONF_FILE_SC5_SCBT_A0 (PFW_DMEM_BASE_SC5_SCBT_A0 - CAL_DATA_CONF_FILE_SIZE)
#define CAL_DATA_CONF_FILE_SCBT_Z0     (PFW_DMEM_BASE_SCBT_Z0 - CAL_DATA_CONF_FILE_SIZE)
#define CAL_DATA_CONF_FILE_SC5_Z0_Z1   (PFW_DMEM_BASE_SC5_Z0_Z1 - CAL_DATA_CONF_FILE_SIZE)

#define SFW_CONFIG_SIZE                (1 * KBYTE)
#define SFW_DMEM_BASE                  (DMEM_BASE + SFW_CONFIG_SIZE)
/* Even though scbt_z1 has bigger DMEM, SFW is using lower sc5_z1 size as of now */
#define SFW_DMEM_SIZE_Z1               (CAL_DATA_CONF_FILE_SC5_Z0_Z1 - SFW_DMEM_BASE)
#define SFW_DMEM_SIZE_A0               (CAL_DATA_CONF_FILE_SC5_SCBT_A0 - SFW_DMEM_BASE)

#define PFW_STACK_SIZE                 (0x1800)
#define IRAM_TX_BASE                   (0x1be000)
#define IRAM_TX_LIMIT                  (0x1be64c)

#endif				//__CPU_H__
