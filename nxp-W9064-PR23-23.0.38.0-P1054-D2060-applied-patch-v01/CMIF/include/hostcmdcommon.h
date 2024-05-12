/** @file hostcmdcommon.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2003-2020 NXP
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

/*****************************************************************************
*
*  $HEADER$
*
*      File name: HostCmdCommon.h
*
*      Purpose: common header
*
*      This file contains the function prototypes, data structure and defines for
*      all the host/station commands. Please check the Eagle 802.11 GUI/Driver/Station 
*      Interface Specification for detailed command information
*
*      Notes:
*
*****************************************************************************/

#ifndef __HOSTCMDCOMMON__H
#define __HOSTCMDCOMMON__H

#include "smac_hal_inf.h"
#include "shal_stats.h"
#ifndef BIT
#define BIT(n) (1 << (n))
#endif

//=============================================================================
//          PUBLIC DEFINITIONS
//=============================================================================
#define PFW_DEBUG_BASE_ADDR                     0x200df800
#define RATE_INDEX_MAX_ARRAY                    14
#define WOW_MAX_STATION                         32

#define SU_MIMO 				                0
#define MU_MIMO 				                1
#define SU_MU_TYPE_CNT			                2	//traffic type, SU and MU

#define ACNT_NCHUNK 16

#if defined(SOC_W906X) || defined(SOC_W9068)
#define MaxMultiDomainCapabilityEntryA 31	//20
#define MaxMultiDomainCapabilityEntryG 1
#else
#define MaxMultiDomainCapabilityEntryA 47	//20
#define MaxMultiDomainCapabilityEntryG 1

#define MAX_SUPPORTED_RATES						12
#define MAX_SUPPORTED_MCS                       32

#define NUM_EDCA_QUEUES					4
#define NUM_HCCA_QUEUES                         0
#define NUM_BA_QUEUES                           0
#define NUM_MGMT_QUEUES                         0

#ifdef MCAST_PS_OFFLOAD_SUPPORT
#define TOTAL_TX_QUEUES                                 NUM_EDCA_QUEUES + NUM_HCCA_QUEUES + NUM_BA_QUEUES + NUM_MGMT_QUEUES + NUMOFAPS
#else
#define TOTAL_TX_QUEUES                                 NUM_EDCA_QUEUES + NUM_HCCA_QUEUES + NUM_BA_QUEUES + NUM_MGMT_QUEUES
#endif

#endif

//***************************************************************************
//***************************************************************************
//
//          Define OpMode for SoftAP/Station mode
//
//  The following mode signature has to be written to PCI scratch register#0
//  right after successfully downloading the last block of firmware and
//  before waiting for firmware ready signature

#define HostCmd_STA_MODE                        0x5A
#define HostCmd_SOFTAP_MODE                     0xA5

#define HostCmd_STA_FWRDY_SIGNATURE             0xF0F1F2F4
#define HostCmd_SOFTAP_FWRDY_SIGNATURE          0xF1F2F4A5

//***************************************************************************
//***************************************************************************

//***************************************************************************

//
// Define Command Processing States and Options
//
#define HostCmd_STATE_IDLE                      0x0000
#define HostCmd_STATE_IN_USE_BY_HOST            0x0001
#define HostCmd_STATE_IN_USE_BY_MINIPORT        0x0002
#define HostCmd_STATE_FINISHED                  0x000f

#define HostCmd_Q_NONE                          0x0000
#define HostCmd_Q_INIT                          0x0001
#define HostCmd_Q_RESET                         0x0002
#define HostCmd_Q_STAT                          0x0003

//
//            Command pending states
//
#define HostCmd_PENDING_ON_NONE                 0x0000
#define HostCmd_PENDING_ON_MISC_OP              0x0001
#define HostCmd_PENDING_ON_INIT                 0x0002
#define HostCmd_PENDING_ON_RESET                0x0003
#define HostCmd_PENDING_ON_SET_OID              0x0004
#define HostCmd_PENDING_ON_GET_OID              0x0005
#define HostCmd_PENDING_ON_CMD                  0x0006
#define HostCmd_PENDING_ON_STAT                 0x0007

#define HostCmd_OPTION_USE_INT                  0x0000
#define HostCmd_OPTION_NO_INT                   0x0001

#define HostCmd_DELAY_NORMAL                    0x00000200	//  512 micro sec
#define HostCmd_DELAY_MIN                       0x00000100	//  256 micro sec
#define HostCmd_DELAY_MAX                       0x00000400	// 1024 micro sec

//***************************************************************************
//
//          16 bit host command code - HHH updated on 110201
//
#define HostCmd_CMD_NONE                        0x0000
#define HostCmd_CMD_CODE_DNLD                   0x0001
#define HostCmd_CMD_GET_HW_SPEC                 0x0003
#define HostCmd_CMD_SET_HW_SPEC                 0x0004
#define HostCmd_CMD_MAC_MULTICAST_ADR           0x0010
#define HostCmd_CMD_802_11_GET_STAT             0x0014
#define HostCmd_CMD_MAC_REG_ACCESS              0x0019
#define HostCmd_CMD_BBP_REG_ACCESS              0x001a
#define HostCmd_CMD_RF_REG_ACCESS               0x001b
#define HostCmd_CMD_802_11_RADIO_CONTROL        0x001c
#define HostCmd_CMD_MEM_ADDR_ACCESS             0x001d
#define HostCmd_CMD_802_11_RF_TX_POWER          0x001e
#define HostCmd_CMD_802_11_TX_POWER             0x001f
#define HostCmd_CMD_802_11_RF_ANTENNA           0x0020

#define HostCmd_CMD_SET_BA_PARAMS               0x0031
#define HostCmd_CMD_SET_CFP                     0x0032
#define HostCmd_CMD_SET_HCCA                    0x0033
#define HostCmd_CMD_SET_MEDIUM_TIME             0x0034

#define HostCmd_CMD_MFG_COMMAND                 0x0040

#define HostCmd_CMD_SET_BEACON                  0x0100
#define HostCmd_CMD_SET_PRE_SCAN                0x0107
#define HostCmd_CMD_SET_POST_SCAN               0x0108
#define HostCmd_CMD_SET_RF_CHANNEL              0x010a
#define HostCmd_CMD_SET_SENDPSPOLL              0x010c
#define HostCmd_CMD_SET_AID                     0x010d
#define HostCmd_CMD_SET_INFRA_MODE              0x010e
#define HostCmd_CMD_SET_G_PROTECT_FLAG          0x010f
#define HostCmd_CMD_SET_RATE                    0x0110
#define HostCmd_CMD_SET_FINALIZE_JOIN           0x0111

#define HostCmd_CMD_802_11_RTS_THSD             0x0113	// formerly 0x002E
#define HostCmd_CMD_802_11_SET_SLOT             0x0114	// formerly 0x002F
#define HostCmd_CMD_SET_EDCA_PARAMS             0x0115
#define HostCmd_CMD_802_11_BOOST_MODE           0x0116

#define HostCmd_CMD_PARENT_TSF                  0x0118
#define HostCmd_CMD_RPI_DENSITY                 0x0119
#define HostCmd_CMD_CCA_BUSY_FRACTION           0x011A

// Define DFS lab commands
#define HostCmd_CMD_STOP_BEACON                 0x011d
#define HostCmd_CMD_802_11H_DETECT_RADAR        0x0120
#define HostCmd_CMD_802_11H_QUERY_DETECT_INFO   0x0121
#define HostCmd_CMD_802_11_RF_TX_POWER_REAL     0x0122

#define HostCmd_CMD_SET_WMM_MODE                0x0123
#define HostCmd_CMD_HT_GUARD_INTERVAL           0x0124
#define HostCmd_CMD_MIMO_CONFIG                 0x0125
#define HostCmd_CMD_SET_FIXED_RATE              0x0126
#define HostCmd_CMD_SET_IES                     0x0127
#define HostCmd_CMD_SET_REGION_POWER            0x0128
#define HostCmd_CMD_SET_LINKADAPT_CS_MODE       0x0129
#define HostCmd_CMD_HT_GF_MODE                  0x0140
#define HostCmd_CMD_HT_TX_STBC                  0x0141
#define HostCmd_CMD_OFFCHAN                     0x0150
#define HostCmd_CMD_OFFCHAN_DBG                 0x0151
#define HostCmd_CMD_DFS_PARAMS                  0x0155

// Define LED control commands
#ifdef LED_CONTROL
#define HostCmd_CMD_LED_SET_INFORMATION         0x0fff
#define HostCmd_CMD_LED_GET_STATE               0x011b
#define HostCmd_CMD_LED_SET_STATE               0x011c
#endif

#define HostCmd_CMD_SET_PASSTHRU                0x01ff
#define HostCmd_CMD_SET_EAPOL_START             0x0201
#define HostCmd_CMD_SET_MAC_ADDR                0x0202
#define HostCmd_CMD_SET_RATE_ADAPT_MODE         0x0203
#define HostCmd_CMD_GET_NOISE_LEVEL             0x0204

#define HostCmd_CMD_GET_WATCHDOG_BITMAP         0x0205
#define HostCmd_CMD_DEL_MAC_ADDR                0x0206

//SoftAP command code
#define HostCmd_CMD_BROADCAST_SSID_ENABLE       0x0050
#define HostCmd_CMD_BSS_START                   0x1100
#define HostCmd_CMD_AP_BEACON                   0x1101
#define HostCmd_CMD_UPDATE_PROBE                0x1102	//Set the Probe response buffer or Update this buffer 30/9/2003
#define HostCmd_CMD_UPDATE_TIM                  0x1103
#define HostCmd_CMD_WDS_ENABLE                  0x1110
#define  HostCmd_CMD_SET_NEW_STN                0x1111
#define HostCmd_CMD_SET_KEEP_ALIVE              0x1112
#define HostCmd_CMD_SET_BURST_MODE              0x1113
#define HostCmd_CMD_SET_APMODE                  0x1114
#define HostCmd_CMD_AP_SCAN_FINISH              0x1117	//Close the AP Scan 2003/12/29
#define HostCmd_CMD_AP_BURST_MODE               0x1118	//???Set the Burst Mode 2004/02/04
#define HostCmd_CMD_AP_SET_STANDBY              0x1119

#define HostCmd_CMD_GET_HW_CAPABILITY           0x1120
#define HostCmd_CMD_SET_SWITCH_CHANNEL          0x1121
#define HostCmd_CMD_SET_SPECTRUM_MGMT           0x1128
#define HostCmd_CMD_SET_POWER_CONSTRAINT        0x1129
#define HostCmd_CMD_SET_COUNTRY_CODE            0x1130

/*
@HWENCR@
Command to update firmware encryption keys.
*/
#if defined(SOC_W906X) || defined(SOC_W9068)
#define HostCmd_CMD_UPDATE_SECURITY_KEY         0x1122
#else
#define HostCmd_CMD_UPDATE_ENCRYPTION			0x1122
#endif
/**
* @STADB@
* Command to update firmware station information database
*/
#define HostCmd_CMD_UPDATE_STADB                0x1123

/**
* Command to enable loopback mode
*/
#define HostCmd_CMD_SET_LOOPBACK_MODE           0x1124
/*
@11E-BA@
Command to create/destroy block ACK
*/
#define HostCmd_CMD_BASTREAM                    0x1125
#define HostCmd_CMD_SET_RIFS                    0x1126
#define HostCmd_CMD_SET_N_PROTECT_FLAG          0x1131
#define HostCmd_CMD_SET_N_PROTECT_OPMODE        0x1132
#define HostCmd_CMD_SET_OPTIMIZATION_LEVEL      0x1133
#define HostCmd_CMD_GET_CALTABLE                0x1134
#define HostCmd_CMD_SET_MIMOPSHT                0x1135
// WSC Simple Config IE Set command
#define HostCmd_CMD_SET_WSC_IE                  0x1136
#define HostCmd_CMD_GET_RATETABLE               0x1137
#define HostCmd_CMD_GET_BEACON                  0x1138
#define HostCmd_CMD_SET_REGION_CODE             0x1139

#define HostCmd_CMD_SET_MAX_DELAY_BY_AC         0x113a

#ifdef POWERSAVE_OFFLOAD
#define HostCmd_CMD_SET_POWERSAVESTATION        0x1140
#define HostCmd_CMD_SET_TIM                     0x1141
#define HostCmd_CMD_GET_TIM                     0x1142
#endif
#define HostCmd_CMD_GET_SEQNO                   0x1143
#define HostCmd_CMD_DWDS_ENABLE                 0x1144
#define HostCmd_CMD_AMPDU_RETRY_RATEDROP_MODE   0x1145
#define HostCmd_CMD_CFEND_ENABLE                0x1146
#define HostCmd_CMD_SET_RXPATHOPT               0x1147
#define HostCmd_CMD_FW_FLUSH_TIMER              0x1148
#define HostCmd_CMD_SET_11N_20_40_CHANNEL_SWITCH 0x1149

#define HostCmd_CMD_SET_CDD                     0x1150
#define HostCmd_CMD_SET_BF                      0x1151
#define HostCmd_CMD_SET_NOACK                   0x1152
#define HostCmd_CMD_SET_NOSTEER                 0x1153
#define HostCmd_CMD_SET_OFDMA                   0x1154
#define HostCmd_CMD_SET_BFTYPE                  0x1155

#ifdef SSU_SUPPORT
#define HostCmd_CMD_SET_SPECTRAL_ANALYSIS       0x1156
#endif

#define HostCmd_CMD_CAU_REG_ACCESS              0x1157
#define HostCmd_CMD_RC_CAL                      0x1158
#define HostCmd_CMD_GET_TEMP                    0x1159
#define HostCmd_CMD_GET_QUEUE_STATS             0x1160
#define HostCmd_CMD_RESET_QUEUE_STATS           0x1161
#define HostCmd_CMD_QSTATS_SET_SA               0x1162

#define HostCmd_CMD_SET_BW_SIGNALLING           0x1163
#define HostCmd_CMD_GET_CONSEC_TXFAIL_ADDR      0x1164
#define HostCmd_CMD_SET_TXFAILLIMIT             0x1165
#define HostCmd_CMD_GET_TXFAILLIMIT             0x1166
#define HostCmd_CMD_SET_WAPI_IE                 0x1167
#define HostCmd_CMD_SET_VHT_OP_MODE             0x1168
#define HostCmd_CMD_LED_CTRL                    0x1169
#define HostCmd_CMD_NEWDP_CTRL                  0x1170
#define HostCmd_CMD_NEWDP_OFFCHAN_START         0x1171
#define HostCmd_CMD_NEWDP_RATEDROP              0x1172
#define HostCmd_CMD_NEWDP_CONFIG_PROM           0x1173
#define HostCmd_CMD_NEWDP_SET_ACNT_BUF_SIZE     0x1174
#define HostCmd_CMD_NEWDP_SENSORD_INIT          0x1175
#define HostCmd_CMD_NEWDP_SENSORD_CMD           0x1176
#define HostCmd_CMD_NEWDP_SET_RX_MCAST          0x1177
#define HostCmd_CMD_NEWDP_SENSORD_SET_BLANKING  0x1178
#define HostCmd_CMD_NEWDP_BFMR_CONFIG           0x1179
#define HostCmd_CMD_NEWDP_BFMR_SBF_OPEN         0x1180	//fw no longer handle this host cmd, can be reused for other host cmd
#define HostCmd_CMD_NEWDP_BFMR_SBF_CLOSE        0x1181	//fw no longer handle this host cmd, can be reused for other host cmd
#define HostCmd_CMD_NEWDP_SET_POWER_PER_RATE    0x1182
#define HostCmd_CMD_NEWDP_GET_POWER_PER_RATE    0x1183
#define HostCmd_CMD_NEWDP_RADIO_STATUS_NOTIFICATION 0x1184
#define HostCmd_CMD_SET_TX_CONTINUOUS           0x1185
#define HostCmd_CMD_NEWDP_AMSDU_CFG             0x1186
#define HostCmd_CMD_NEWDP_RX_DETECT             0x1187
#define HostCmd_CMD_SET_SKU                     0x1188
#define HostCmd_CMD_NEWDP_DMATHREAD_START       0x1189
#define HostCmd_CMD_GET_FW_REGION_CODE          0x118A
#if defined(SOC_W906X) || defined(SOC_W9068)
#define HostCmd_CMD_GET_EEPROM_PWR_TBL          0x118B
#else
#define HOSTCMD_CMD_GET_DEVICE_PWR_TBL		0x118B
#endif

#define HostCmd_CMD_GET_MU_SET                  0x1190
#define HostCmd_CMD_SET_MU_SET                  0x1191
#define HostCmd_CMD_GET_TLV_SET                 0x1192
#define HostCmd_CMD_SET_TLV_SET                 0x1193
#define HostCmd_CMD_EEPROM_SET                  0x1194
#define HostCmd_CMD_EEPROM_ACCESS               0x1195
#define HostCmd_CMD_NEWDP_OFFCHAN_PWR           0x1196
#define HostCmd_CMD_NEWDP_NDPA_USETA            0x1197
#define HostCmd_CMD_GET_SYS_LOAD                0x1198
#define HostCmd_CMD_SET_RATETABLE               0x1199
#if defined(SOC_W906X) || defined(SOC_W9068)
#define HostCmd_CMD_SET_WTP_MODE		0x119a
#else
#define HostCmd_CMD_SET_RTS_RETRY		0x119a
#ifdef WTP_SUPPORT
#define HostCmd_CMD_SET_WTP_MODE		0x1172
#endif
#endif

#define HostCmd_CMD_GET_PHY_BW                  0x119b

#if !defined(SOC_W906X) && !defined(SOC_W9068)
#define HostCmd_CMD_SET_RESET_RATE_MODE         0x119c
#define HOSTCMD_CMD_SET_ALPHA_TIMING_FC         0x119d
#define HOSTCMD_CMD_SET_RATE_UPDATE_TICKS       0x119e
#define HOSTCMD_CMD_SET_CUSTOM_RATE             0x119f
#endif

#define HostCmd_CMD_SET_RRM                     0x11a0
#define HostCmd_CMD_SET_CH_UTIL                 0x11a1
#define HostCmd_CMD_SET_QUIET                   0x11a2
#define HostCmd_CMD_SET_MBSSID_SET				0x11a3

#if defined(SOC_W906X) || defined(SOC_W9068)
#define HOSTCMD_CMD_BCN_GPIO17_TOGGLE           0x11a4
#endif

//twt
#define HostCmd_CMD_TWT_PARAM				    0x11a5
#define HostCmd_CMD_SR_PARAM				    0x11a6

#if defined(SOC_W906X) || defined(SOC_W9068)
#define HostCmd_CMD_OBW16_11B                   0x11a7
#endif

#define HostCmd_CMD_SET_ACNT_STOP               0x11a8
#define HostCmd_CMD_GET_STA_STATS               0x11a9

#define HostCmd_CMD_SET_OFDMA_SET               0x11aa
#define HostCmd_CMD_SET_ULMU_SET                0x11ab
#define HostCmd_CMD_SET_ANCT_WITH_MU            0x11ac

#define HostCmd_CMD_GET_MVL_RADIO_STATUS        0x1201
#define HostCmd_CMD_CORE_DUMP_DIAG_MODE         0x1202
#define HostCmd_CMD_GET_FW_CORE_DUMP            0x1203
#define HostCmd_CMD_GET_FW_CORE_MEM_DUMP        0x1204

#ifdef WMM_AC_EDCA
#define HostCmd_CMD_SET_BSS_LOAD_AAC            0x1205
#endif

#if !defined(SOC_W906X) && !defined(SOC_W9068)
#define HostCmd_CMD_SET_MTX_GET					0x1300
#define HostCmd_CMD_SET_MTX_PUT					0x1301
#endif

// The test command.
#define HostCmd_CMD_TEST_SET_RATE_TABLE         0x2000

// The security test command.
#define HostCmd_CMD_FIPS_TEST                   0x2001

//Debug command
#define HostCmd_CMD_SET_TXDROP                  0x2002

#ifdef DSP_COMMAND
// The dsp command.
#define HostCmd_CMD_DSP_CMD                     0x2003
#endif

#define HostCmd_CMD_TRIGGER_FRAME              0x2004
#define HostCmd_CMD_TX_FRAME_TEST              0x2005
#define HostCmd_CMD_WFA_TEST                   0x2006
#define HostCmd_CMD_MIB_CFG                    0x2007
#define HostCmd_CMD_SCHED_MODE_CFG             0x2008

#ifdef MRVL_MUG_ENABLE

#define HostCmd_CMD_GET_MU_INFO                 0x3001
#define HostCmd_CMD_SET_MU_CONFIG               0x3002
#define HostCmd_CMD_SET_MU_DMA                  0x3003
#define HostCmd_CMD_MUG_ENABLE                  0x3004
#endif

#ifdef AIRTIME_FAIRNESS
#define HostCmd_CMD_ATF_ENABLE                  0x3101
#define HostCmd_CMD_SET_ATF_CFG                 0x3102
#define HostCmd_CMD_GET_ATF_CFG                 0x3103
#define HostCmd_CMD_ATF_DEBUG_ENABLE            0x3104
#define HostCmd_CMD_SET_ATF_DMA                 0x3105
#define HostCmd_CMD_ATF_TRANSFERT_DONE          0x3106
#endif /* AIRTIME_FAIRNESS */

#define HostCmd_CMD_SET_AP_CBMODE               0x3201
#define HostCmd_CMD_SET_STA_CB_NOACK            0x3202
#define HostCmd_CMD_GET_STA_CB_PARAMS_SYNC      0x3203
#define HostCmd_CMD_SET_STA_CB_PARAMS_SYNC      0x3204

#define HostCmd_CMD_SET_MCAST_CTS_TO_SELF		0x4001
#define HostCmd_CMD_MU_USER_POSITION    		0x4002

#define HostCmd_CMD_SET_FIXED_PE    		    0x4003
#define HostCmd_CMD_SET_BEAM_CHANGE             0x4004
#define HostCmd_CMD_PROTECTION_MODE             0x4005
#ifdef WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER
#define HostCmd_CMD_COEX_CONF_ACCESS            0x4006
#endif

#define HostCmd_CMD_SET_STA_AWAKE               0x4007

//***************************************************************************
//
//          16 bit RET code, MSB is set to 1
//
#define HostCmd_RET_NONE                        0x8000
#define HostCmd_RET_HW_SPEC_INFO                0x8003
#define HostCmd_RET_MAC_MULTICAST_ADR           0x8010
#define HostCmd_RET_802_11_STAT                 0x8014
#define HostCmd_RET_MAC_REG_ACCESS              0x8019
#define HostCmd_RET_BBP_REG_ACCESS              0x801a
#define HostCmd_RET_RF_REG_ACCESS               0x801b
#define HostCmd_RET_802_11_RADIO_CONTROL        0x801c
#define HostCmd_RET_802_11_RF_CHANNEL           0x801d
#define HostCmd_RET_802_11_RF_TX_POWER          0x801e
#define HostCmd_RET_802_11_RSSI                 0x801f
#define HostCmd_RET_802_11_RF_ANTENNA           0x8020
#define HostCmd_RET_802_11_PS_MODE              0x8021
#define HostCmd_RET_802_11_DATA_RATE            0x8022

#define HostCmd_RET_MFG_COMMAND                 0x8040

#define HostCmd_RET_802_11_RTS_THSD             0x8113	// formerly 0x802E

#define HostCmd_RET_802_11_SET_SLOT             0x8114	// formerly 0x802F

#if defined(SOC_W906X) || defined(SOC_W9068)
#define HostCmd_RET_SET_EDCA_PARAMS             0x8115
#else
#define HostCmd_RET_802_11_SET_CWMIN_MAX        0x8115
#endif
#define HostCmd_RET_802_11_BOOST_MODE           0x8116

#define HostCmd_RET_PARENT_TSF                  0x8118
#define HostCmd_RET_RPI_DENSITY                 0x8119
#define HostCmd_RET_CCA_BUSY_FRACTION           0x811A

#define HostCmd_RET_SET_EAPOL_START             0x8201
#define HostCmd_RET_SET_MAC_ADDR                0x8202

#define HostCmd_RET_SET_BEACON                  0x8100
#define HostCmd_RET_SET_PRE_SCAN                0x8107
#define HostCmd_RET_SET_POST_SCAN               0x8108
#define HostCmd_RET_SET_RF_CHANNEL              0x810a
#define HostCmd_RET_SET_SENDPSPOLL              0x810c
#define HostCmd_RET_SET_AID                     0x810d
#define HostCmd_RET_SET_INFRA_MODE              0x810e
#define HostCmd_RET_SET_G_PROTECT_FLAG          0x810f
#define HostCmd_RET_SET_RATE                    0x8110
#define HostCmd_RET_SET_FINALIZE_JOIN           0x8111

#define HostCmd_RET_SET_PASSTHRU                0x81ff

// Define LED control RET code
#ifdef LED_CONTROL
#define HostCmd_RET_LED_SET_INFORMATION         0x8fff
#define HostCmd_RET_LED_GET_STATE               0x811b
#define HostCmd_RET_LED_SET_STATE               0x811c
#endif

#define HostCmd_RET_STOP_BEACON                 0x811d

#define HostCmd_RET_SET_WMM_MODE                0x8123

#define HostCmd_RET_HT_GUARD_INTERVAL           0x8124
#define HostCmd_RET_MIMO_CONFIG                 0x8125

//SoftAP command code
#define HostCmd_RET_GET_HW_CAPABILITY           0x9120
#define HostCmd_RET_SET_SWITCH_CHANNEL          0x9121
/*
@HWENCR@
ID for encryption response from firmware
*/
#define HostCmd_RET_UPDATE_ENCRYPTION           0x9122
/**
* @STADB@
* Command to update firmware station information database
*/
#define HostCmd_RET_UPDATE_STADB                0x9123

/**
* Command to enable loopback mode
*/
#define HostCmd_RET_SET_LOOPBACK_MODE           0x9124
/*
@11E-BA@
Command to create/destroy block ACK
*/
#define HostCmd_RET_BASTREAM                    0x9125

//***************************************************************************
//
//          Define general result code for each command
//
#define HostCmd_RESULT_OK                       0x0000	// OK
#define HostCmd_RESULT_ERROR                    0x0001	// Genenral error
#define HostCmd_RESULT_NOT_SUPPORT              0x0002	// Command is not valid
#define HostCmd_RESULT_PENDING                  0x0003	// Command is pending (will be processed)
#define HostCmd_RESULT_BUSY                     0x0004	// System is busy (command ignored)
#define HostCmd_RESULT_PARTIAL_DATA             0x0005	// Data buffer is not big enough
#define HostCmd_RESULT_SMAC_CMD_BUFF_FULL       0x0006	// SMAC no buffer available
#define HostCmd_RESULT_BSS_INDEX_INVALID        0x0007	// Bss Index (MacId)  out of range
#define HostCmd_RESULT_BSS_NOT_FOUND            0x0008	// bss entry not existed
#define HostCmd_RESULT_STA_NOT_FOUND            0x0009	// sta entry not existed
#define HostCmd_RESULT_ABORT                    0x000a	// Command aborted/FW in diag mode
#define HostCmd_RESULT_STA_INDEX_INVALID        0x000b	// sta index out of range
#define HostCmd_RESULT_OFFCHAN_BCN_GUARD        0x000c	// Off-channel is failed due to beacon guard period
#define HostCmd_RESULT_OFFCHAN_IN_PROCESS       0x000d	// Off-channel is failed due to previous request is in process

#define HostCmd_RESULT_LAST                     0x000e	// Please keep this value to the last one of HostCmd_RESULT,
						       //when insert a new definition

#define HostCmd_FINISHED                        0x8000	//This Status Implies FW Processed the Command

//***************************************************************************
//
//          Definition of action or option for each command
//
//          Define general purpose action
//
#define HostCmd_ACT_GEN_READ                    0x0000
#define HostCmd_ACT_GEN_WRITE                   0x0001
#define HostCmd_ACT_GEN_GET                     0x0000
#define HostCmd_ACT_GEN_SET                     0x0001
#define HostCmd_ACT_GEN_DEL                     0x0002
#define HostCmd_ACT_GEN_OFF                     0x0000
#define HostCmd_ACT_GEN_ON                      0x0001

#define HostCmd_ACT_DIFF_CHANNEL                0x0002
#define HostCmd_ACT_GEN_SET_LIST                0x0002
#define HostCmd_ACT_GEN_GET_LIST                0x0003

//          Define action or option for HostCmd_FW_USE_FIXED_RATE
#define HostCmd_ACT_USE_FIXED_RATE              0x0001
#define HostCmd_ACT_NOT_USE_FIXED_RATE          0x0002
//          Define action or option for HostCmd_CMD_802_11_AUTHENTICATE
#define HostCmd_ACT_AUTHENTICATE                0x0001
#define HostCmd_ACT_DEAUTHENTICATE              0x0002

//          Define action or option for HostCmd_CMD_802_11_ASSOCIATE
#define HostCmd_ACT_ASSOCIATE                   0x0001
#define HostCmd_ACT_DISASSOCIATE                0x0002
#define HostCmd_ACT_REASSOCIATE                 0x0003

#define HostCmd_CAPINFO_ESS                     0x0001
#define HostCmd_CAPINFO_IBSS                    0x0002
#define HostCmd_CAPINFO_CF_POLLABLE             0x0004
#define HostCmd_CAPINFO_CF_REQUEST              0x0008
#define HostCmd_CAPINFO_PRIVACY                 0x0010

//          Define action or option for HostCmd_CMD_802_11_SET_WEP
//#define HostCmd_ACT_ENABLE                    0x0001 // Use MAC control for WEP on/off
//#define HostCmd_ACT_DISABLE                   0x0000
#define HostCmd_ACT_ADD                         0x0002
#define HostCmd_ACT_REMOVE                      0x0004
#define HostCmd_ACT_USE_DEFAULT                 0x0008

#define HostCmd_TYPE_WEP_40_BIT                 0x0001	// 40 bit
#define HostCmd_TYPE_WEP_104_BIT                0x0002	// 104 bit
#define HostCmd_TYPE_WEP_128_BIT                0x0003	// 128 bit
#define HostCmd_TYPE_WEP_TX_KEY                 0x0004	// TX WEP

#define HostCmd_NUM_OF_WEP_KEYS                 4

#define HostCmd_WEP_KEY_INDEX_MASK              0x3fffffff

//          Define action or option for HostCmd_CMD_802_11_RESET
#define HostCmd_ACT_HALT                        0x0001
#define HostCmd_ACT_RESTART                     0x0002

//          Define action or option for HostCmd_CMD_802_11_SCAN
#define HostCmd_BSS_TYPE_BSS                    0x0001
#define HostCmd_BSS_TYPE_IBSS                   0x0002
#define HostCmd_BSS_TYPE_ANY                    0x0003

//          Define action or option for HostCmd_CMD_802_11_SCAN
#define HostCmd_SCAN_TYPE_ACTIVE                0x0000
#define HostCmd_SCAN_TYPE_PASSIVE               0x0001

#define HostCmd_SCAN_802_11_B_CHANNELS          11

#define HostCmd_SCAN_MIN_CH_TIME                6
#define HostCmd_SCAN_MAX_CH_TIME                12

#define HostCmd_SCAN_PROBE_DELAY_TIME           0

//          Define action or option for HostCmd_CMD_802_11_QUERY_STATUS
#define HostCmd_STATUS_FW_INIT                  0x0000
#define HostCmd_STATUS_FW_IDLE                  0x0001
#define HostCmd_STATUS_FW_WORKING               0x0002
#define HostCmd_STATUS_FW_ERROR                 0x0003
#define HostCmd_STATUS_FW_POWER_SAVE            0x0004

#define HostCmd_STATUS_MAC_RX_ON                0x0001
#define HostCmd_STATUS_MAC_TX_ON                0x0002
#define HostCmd_STATUS_MAC_LOOP_BACK_ON         0x0004
#define HostCmd_STATUS_MAC_WEP_ENABLE           0x0008
#define HostCmd_STATUS_MAC_INT_ENABLE           0x0010

//          Define action or option for HostCmd_CMD_MAC_CONTROL
#define HostCmd_ACT_MAC_RX_ON                   0x0001
#define HostCmd_ACT_MAC_TX_ON                   0x0002
#define HostCmd_ACT_MAC_LOOPBACK_ON             0x0004
#define HostCmd_ACT_MAC_WEP_ENABLE              0x0008
#define HostCmd_ACT_MAC_INT_ENABLE              0x0010
#define HostCmd_ACT_MAC_MULTICAST_ENABLE        0x0020
#define HostCmd_ACT_MAC_BROADCAST_ENABLE        0x0040
#define HostCmd_ACT_MAC_PROMISCUOUS_ENABLE      0x0080
#define HostCmd_ACT_MAC_ALL_MULTICAST_ENABLE    0x0100

//          Define action or option or constant for HostCmd_CMD_MAC_MULTICAST_ADR
#define HostCmd_SIZE_MAC_ADR                    6
#define HostCmd_MAX_MCAST_ADRS                  32

#define NDIS_PACKET_TYPE_DIRECTED               0x00000001
#define NDIS_PACKET_TYPE_MULTICAST              0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST          0x00000004
#define NDIS_PACKET_TYPE_BROADCAST              0x00000008
#define NDIS_PACKET_TYPE_PROMISCUOUS            0x00000020

//          Define action or option for HostCmd_CMD_802_11_SNMP_MIB
#define HostCmd_TYPE_MIB_FLD_BOOLEAN            0x0001	// Boolean
#define HostCmd_TYPE_MIB_FLD_INTEGER            0x0002	// 32 u8 unsigned integer
#define HostCmd_TYPE_MIB_FLD_COUNTER            0x0003	// Counter
#define HostCmd_TYPE_MIB_FLD_OCT_STR            0x0004	// Octet string
#define HostCmd_TYPE_MIB_FLD_DISPLAY_STR        0x0005	// String
#define HostCmd_TYPE_MIB_FLD_MAC_ADR            0x0006	// MAC address
#define HostCmd_TYPE_MIB_FLD_IP_ADR             0x0007	// IP address
#define HostCmd_TYPE_MIB_FLD_WEP                0x0008	// WEP

//          Define action or option for HostCmd_CMD_802_11_RADIO_CONTROL
#define HostCmd_TYPE_AUTO_PREAMBLE              0x0001
#define HostCmd_TYPE_SHORT_PREAMBLE             0x0002
#define HostCmd_TYPE_LONG_PREAMBLE              0x0003

#define SET_AUTO_PREAMBLE                       0x05
#define SET_SHORT_PREAMBLE                      0x03
#define SET_LONG_PREAMBLE                       0x01
//          Define action or option for CMD_802_11_RF_CHANNEL
#define HostCmd_TYPE_802_11A                    0x0001
#define HostCmd_TYPE_802_11B                    0x0002

//          Define action or option for HostCmd_CMD_802_11_RF_TX_POWER
#define HostCmd_ACT_TX_POWER_OPT_SET_HIGH       0x0003
#define HostCmd_ACT_TX_POWER_OPT_SET_MID        0x0002
#define HostCmd_ACT_TX_POWER_OPT_SET_LOW        0x0001
#define HostCmd_ACT_TX_POWER_OPT_SET_AUTO       0x0000

#define HostCmd_ACT_TX_POWER_LEVEL_MIN          0x000e	// in dbm
#define HostCmd_ACT_TX_POWER_LEVEL_GAP          0x0001	// in dbm
//          Define action or option for HostCmd_CMD_802_11_DATA_RATE
#define HostCmd_ACT_SET_TX_AUTO                 0x0000
#define HostCmd_ACT_SET_TX_FIX_RATE             0x0001
#define HostCmd_ACT_GET_TX_RATE                 0x0002

#define HostCmd_ACT_SET_RX                      0x0001
#define HostCmd_ACT_SET_TX                      0x0002
#define HostCmd_ACT_SET_BOTH                    0x0003
#define HostCmd_ACT_GET_RX                      0x0004
#define HostCmd_ACT_GET_TX                      0x0008
#define HostCmd_ACT_GET_BOTH                    0x000c

#define TYPE_ANTENNA_DIVERSITY                  0xffff

//          Define action or option for HostCmd_CMD_802_11_PS_MODE
#define HostCmd_TYPE_CAM                        0x0000
#define HostCmd_TYPE_MAX_PSP                    0x0001
#define HostCmd_TYPE_FAST_PSP                   0x0002

//          Define LED control command state
#define HostCmd_STATE_LED_HALTED                0x00
#define HostCmd_STATE_LED_IDLE                  0x01
#define HostCmd_STATE_LED_SCAN                  0x02
#define HostCmd_STATE_LED_AUTHENTICATED         0x03
#define HostCmd_STATE_LED_BSS_ASSO_IN_PROGRESS  0x04
#define HostCmd_STATE_LED_BSS_ASSOCIATED        0x05
#define HostCmd_STATE_LED_IBSS_JOINED           0x06
#define HostCmd_STATE_LED_IBSS_STARTED          0x07
#define HostCmd_STATE_LED_TX_TRAFFIC            0x08
#define HostCmd_STATE_LED_RX_TRAFFIC            0x09
#define HostCmd_STATE_LED_TX_TRAFFIC_LOW_RATE   0x0a
#define HostCmd_STATE_LED_RX_TRAFFIC_LOW_RATE   0x0b
#define HostCmd_STATE_LED_TX_TRAFFIC_HIGH_RATE  0x0c
#define HostCmd_STATE_LED_RX_TRAFFIC_HIGH_RATE  0x0d

#define HostCmd_STATE_LED_ENCYP_ON              0x10
#define HostCmd_STATE_LED_AP_MODE               0x11
#define HostCmd_STATE_LED_IN_PS_MODE            0x12
#define HostCmd_STATE_LED_IN_MAX_PSP_PS_MODE    0x13
#define HostCmd_STATE_LED_IN_FAST_PSP_PS_MODE   0x14
#define HostCmd_STATE_LED_IN_CMS_PS_MODE        0x15

#define HostCmd_STATE_LED_B_BAND_RF_ON          0x20
#define HostCmd_STATE_LED_B_BAND_RF_OFF         0x21
#define HostCmd_STATE_LED_A_BAND_RF_ON          0x22
#define HostCmd_STATE_LED_A_BAND_RF_OFF         0x23
#define HostCmd_STATE_LED_B_MODE_ON             0x24
#define HostCmd_STATE_LED_B_MODE_OFF            0x25
#define HostCmd_STATE_LED_G_MODE_ON             0x26
#define HostCmd_STATE_LED_G_MODE_OFF            0x27
#define HostCmd_STATE_LED_A_MODE_ON             0x28
#define HostCmd_STATE_LED_A_MODE_OFF            0x29

#define HostCmd_STATE_LED_1_MBPS                0x30
#define HostCmd_STATE_LED_2_MBPS                0x31
#define HostCmd_STATE_LED_5_AND_HALF_MBPS       0x32
#define HostCmd_STATE_LED_11_MBPS               0x33
#define HostCmd_STATE_LED_22_MBPS               0x34
#define HostCmd_STATE_LED_6_MBPS                0x35
#define HostCmd_STATE_LED_9_MBPS                0x36
#define HostCmd_STATE_LED_12_MBPS               0x37
#define HostCmd_STATE_LED_18_MBPS               0x38
#define HostCmd_STATE_LED_24_MBPS               0x39
#define HostCmd_STATE_LED_36_MBPS               0x3a
#define HostCmd_STATE_LED_48_MBPS               0x3b
#define HostCmd_STATE_LED_54_MBPS               0x3c
#define HostCmd_STATE_LED_72_MBPS               0x3d

#define HostCmd_STATE_LED_DIAG_MODE             0xfd
#define HostCmd_STATE_LED_FW_UPDATE             0xfe
#define HostCmd_STATE_LED_HW_ERROR              0xff

//          Define LED control MASK
#define HostCmd_MASK_TYPE_PIN_MASK              0x00
#define HostCmd_MASK_TYPE_POWER_ON              0x01
#define HostCmd_MASK_TYPE_POWER_OFF             0x02

//          Define LED control command pattern
#define HostCmd_PATTERN_LED_37_MS_BLINK         0x00
#define HostCmd_PATTERN_LED_74_MS_BLINK         0x01
#define HostCmd_PATTERN_LED_149_MS_BLINK        0x02
#define HostCmd_PATTERN_LED_298_MS_BLINK        0x03
#define HostCmd_PATTERN_LED_596_MS_BLINK        0x04
#define HostCmd_PATTERN_LED_1192_MS_BLINK       0x05

#define HostCmd_PATTERN_LED_250_MS_STRETCH      0x12
#define HostCmd_PATTERN_LED_250_MS_OFF          0x22

#define HostCmd_PATTERN_LED_AUTO                0xfc
#define HostCmd_PATTERN_LED_STAY_CURRENT        0xfd
#define HostCmd_PATTERN_LED_STAY_OFF            0xfe
#define HostCmd_PATTERN_LED_STAY_ON             0xff

//=============================================================================
//            HOST COMMAND DEFINITIONS
//=============================================================================

#ifdef NDIS_MINIPORT_DRIVER
#pragma pack(1)
#endif

//
//          Definition of data structure for each command
//
//          Define general data structure
typedef PACK_START struct tagFWCmdHdr {
	u16 Cmd;
	u16 Length;
	u8 SeqNum;
	u8 macid;
	u16 Result;
} PACK_END host_MsgHdr_t, FWCmdHdr, *PFWCmdHdr;

#if defined(SOC_W906X) || defined(SOC_W9068)
typedef struct _HostCmd_DS_SET_HW_SPEC {
	FWCmdHdr CmdHdr;
	u8 Version;		// HW revision
	u8 HostIf;		// Host interface
	u16 NumOfMCastAdr;	// Max. number of Multicast address FW can handle
	u8 PermanentAddr[6];	// MAC address
	u16 RegionCode;		// Region Code
	u32 FWReleaseNumber;	// 4 byte of FW release number, example 0x1234=1.2.3.4
	u32 ulFwAwakeCookie;	// Firmware awake cookie - used to ensure that the device is not in sleep mode
	u32 DeviceCaps;		// Device capabilities (see above)
	//    SUPPORTED_MCS_BITMAP    DeviceMcsBitmap;                // Device supported MCS bitmap

	u32 RxPdWrPtr;		// Rx shared memory queue
	u32 NumTxQueues;	// Actual number of TX queues in WcbBase array
#ifdef MV_CPU_LE
	u32 MaxAMsduSize:2;	// Max AMSDU size (00 - AMSDU Disabled, 01 - 4K, 10 - 8K, 11 - not defined)
	u32 ImplicitAmpduBA:1;	// Indicates supported AMPDU type (1 = implicit, 0 = explicit (default))
	u32 disablembss:1;	// indicates mbss features disable in FW
	u32 hostFormBeacon:1;
	u32 hostFormProbeResponse:1;
	u32 hostPowerSave:1;
	u32 hostEncrDecrMgt:1;
	u32 hostIntraBssOffload:1;
	u32 hostIVOffload:1;
	u32 hostEncrDecrFrame:1;
	u32 hostPciIntrType:3;
	u32 Reserved:18;	// Reserved
#else				//MV_CPU_BE  Pete, check alignment?
	u32 hostEncrDecrMgt:1;
	u32 hostPowerSave:1;
	u32 hostFormProbeResponse:1;
	u32 hostFormBeacon:1;
	u32 disablembss:1;	// indicates mbss features disable in FW
	u32 ImplicitAmpduBA:1;	// Indicates supported AMPDU type (1 = implicit, 0 = explicit (default))
	u32 MaxAMsduSize:2;	// Max AMSDU size (00 - AMSDU Disabled, 01 - 4K, 10 - 8K, 11 - not defined)
	u32 Reserved0:2;
	u32 hostPciIntrType:3;
	u32 hostEncrDecrFrame:1;
	u32 hostIVOffload:1;
	u32 hostIntraBssOffload:1;
	u32 Reserved:16;
#endif

	u32 TxWcbNumPerQueue;
	u32 TotalRxWcb;

	u32 eventq_addr;	// Event buffer queue address (base address of the buffer)
	u16 eventq_nums;	// Event buffer queue number (# of items
	u16 eventq_size;	// Event buffer queue size (size of each item)

	u32 acntBufSize;	// Total accounting buffer size of multiple chunks
	u32 AcntBaseAddr[ACNT_NCHUNK];	// Rx shared memory queue
	u32 log2Chunk;		// Log 2 chunk size
} __attribute__ ((packed)) HostCmd_DS_SET_HW_SPEC, *PHostCmd_DS_SET_HW_SPEC;

typedef PACK_START struct _HostCmd_DS_GET_HW_SPEC {
	FWCmdHdr CmdHdr;
	u8 Version;		/* version of the HW                    */
	u8 HostIf;		/* host interface                       */
	u16 NumOfWCB;		/* Max. number of WCB FW can handle     */
	u16 NumOfMCastAddr;	/* MaxNbr of MC addresses FW can handle */
	u8 PermanentAddr[6];	/* MAC address programmed in HW         */
	u16 RegionCode;
	u16 NumberOfAntenna;	/* Number of antenna used      */
	u32 FWReleaseNumber;	/* 4 byte of FW release number */
	u32 SFWReleaseNumber;	/* 4 byte of SFW release number */
	u32 WcbBase0;
	u32 RxPdWrPtr;
	u32 RxPdRdPtr;
	u32 ulFwAwakeCookie;
	u16 ulShalVersion;
	u16 Reserved;
	u32 ulSmacVersion;
} PACK_END HostCmd_DS_GET_HW_SPEC, *PHostCmd_DS_GET_HW_SPEC;
#else
typedef struct _HostCmd_DS_SET_HW_SPEC {
	FWCmdHdr CmdHdr;
	u8 Version;		// HW revision
	u8 HostIf;		// Host interface
	u16 NumOfMCastAdr;	// Max. number of Multicast address FW can handle
	u8 PermanentAddr[6];	// MAC address
	u16 RegionCode;		// Region Code
	u32 FWReleaseNumber;	// 4 byte of FW release number, example 0x1234=1.2.3.4
	u32 ulFwAwakeCookie;	// Firmware awake cookie - used to ensure that the device is not in sleep mode
	u32 DeviceCaps;		// Device capabilities (see above)
	//      SUPPORTED_MCS_BITMAP    DeviceMcsBitmap;                                // Device supported MCS bitmap

	u32 RxPdWrPtr;		// Rx shared memory queue
	u32 NumTxQueues;	// Actual number of TX queues in WcbBase array
#ifdef MCAST_PS_OFFLOAD_SUPPORT
	u32 WcbBase[4 + NUMOFAPS];	// TX WCB Ring
#else
	u32 WcbBase[4];		// TX WCB Rings
#endif
#ifdef MV_CPU_LE
	u32 MaxAMsduSize:2;	// Max AMSDU size (00 - AMSDU Disabled, 01 - 4K, 10 - 8K, 11 - not defined)
	u32 ImplicitAmpduBA:1;	// Indicates supported AMPDU type (1 = implicit, 0 = explicit (default))
	u32 disablembss:1;	// indicates mbss features disable in FW
	u32 hostFormBeacon:1;
	u32 hostFormProbeResponse:1;
	u32 hostPowerSave:1;
	u32 hostEncrDecrMgt:1;
	u32 hostIntraBssOffload:1;
	u32 hostIVOffload:1;
	u32 hostEncrDecrFrame:1;
	u32 Reserved:21;	// Reserved
#else				//MV_CPU_BE  Pete, check alignment?
	u32 hostEncrDecrMgt:1;
	u32 hostPowerSave:1;
	u32 hostFormProbeResponse:1;
	u32 hostFormBeacon:1;
	u32 disablembss:1;	// indicates mbss features disable in FW
	u32 ImplicitAmpduBA:1;	// Indicates supported AMPDU type (1 = implicit, 0 = explicit (default))
	u32 MaxAMsduSize:2;	// Max AMSDU size (00 - AMSDU Disabled, 01 - 4K, 10 - 8K, 11 - not defined)
	u32 Reserved0:5;
	u32 hostEncrDecrFrame:1;
	u32 hostIVOffload:1;
	u32 hostIntraBssOffload:1;
	u32 Reserved:16;
#endif

	u32 TxWcbNumPerQueue;
	u32 TotalRxWcb;

	u32 acntBufSize;	// Total accounting buffer size of multiple chunks
#ifdef NEWDP_ACNT_CHUNKS
	u32 AcntBaseAddr[ACNT_NCHUNK];	// Rx shared memory queue
	u32 log2Chunk;		// Log 2 chunk size
#else
	u32 AcntBaseAddr;
#endif

} __attribute__ ((packed)) HostCmd_DS_SET_HW_SPEC, *PHostCmd_DS_SET_HW_SPEC;
typedef struct _HostCmd_DS_GET_HW_SPEC {
	FWCmdHdr CmdHdr;
	u8 Version;		/* version of the HW                    */
	u8 HostIf;		/* host interface                       */
	u16 NumOfWCB;		/* Max. number of WCB FW can handle     */
	u16 NumOfMCastAddr;	/* MaxNbr of MC addresses FW can handle */
	u8 PermanentAddr[6];	/* MAC address programmed in HW         */
	u16 RegionCode;
	u16 NumberOfAntenna;	/* Number of antenna used      */
	u32 FWReleaseNumber;	/* 4 byte of FW release number */
#ifndef NEW_DP
	u32 WcbBase0;
#else
	u32 TxDescLimit;	/*Limit tx desc to queue into fw, value get from fw */
#endif
	u32 RxPdWrPtr;
	u32 RxPdRdPtr;
	u32 ulFwAwakeCookie;
#ifndef NEW_DP
	u32 WcbBase[TOTAL_TX_QUEUES - 1];
#endif
} __attribute__ ((packed)) HostCmd_DS_GET_HW_SPEC;
#endif /* SOC_W906X */

#define SIZE_FJ_BEACON_BUFFER 128
typedef PACK_START struct _HostCmd_FW_SET_FINALIZE_JOIN {
	FWCmdHdr CmdHdr;
	u32 ulSleepPeriod;	// Number of beacon periods to sleep
	u8 BeaconBuffer[SIZE_FJ_BEACON_BUFFER];
} PACK_END HostCmd_FW_SET_FINALIZE_JOIN, *PHostCmd_FW_SET_FINALIZE_JOIN;

#define HW_SPEC_WCBBASE_OFFSET   0
#define HW_SPEC_WCBBASE1_OFFSET  4
typedef PACK_START struct _HostCmd_MFG_CMD {

	u32 MfgCmd;
	u32 Action;
	u32 Error;
} PACK_END HostCmd_MFG_CMD, *PHostCmd_MFG_CMD;
//          Define data structure for HostCmd_CMD_MAC_MULTICAST_ADR
typedef PACK_START struct _HostCmd_DS_MAC_MULTICAST_ADR {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 NumOfAdrs;
	u8 MACList[HostCmd_SIZE_MAC_ADR * HostCmd_MAX_MCAST_ADRS];
} PACK_END HostCmd_DS_MAC_MULTICAST_ADR, *PHostCmd_DS_MAC_MULTICAST_ADR;

// called before a mlme bss scan in lounched
// to configure the hardware for the scan
// also used as read in init and disconnect
// This cmd is tied to settin packet filtering
// for scanning in both init and scan calls
typedef PACK_START struct tagHostCmd_FW_SET_PRESCAN {
	FWCmdHdr CmdHdr;
	u32 TsfTime;
} PACK_END HostCmd_FW_SET_PRESCAN, *PHostCmd_FW_SET_PRESCAN,
	HostCmd_FW_SET_DISCONNECT, *PHostCmd_FW_SET_DISCONNECT;

typedef PACK_START struct _tsf_info_t {
	u64 HwTsfTime;
	u64 BssTsfBase;
	u64 BssTsfTime;
} PACK_END tsf_info_t;

typedef PACK_START struct tagHostCmd_FW_GET_TSF {
	FWCmdHdr CmdHdr;
	tsf_info_t tsfInfo;
} PACK_END HostCmd_FW_GET_TSF, *PHostCmd_FW_GET_TSF;

#ifdef AP_TWT
#define TWT_WFA_CODEWORD   0xAA
#define TWT_WFA_RXMODE     0x11
#define TWT_WFA_NONRXMODE  0x66
typedef PACK_START struct tagHostCmd_FW_DS_TWT_PARAM {
	FWCmdHdr CmdHdr;
	u8 Action;
	u8 Stamac[6];
	u8 flowid;
	twt_param_t twtparam;
	//for WFA iTWT cases of monitoring RX mode is started or not
	u32 IsTWTRxRunningAddr;	//PFW feedback the address of the flag.
} HostCmd_FW_DS_TWT_PARAM, *PHostCmd_FW_DS_TWT_PARAM;
#endif

typedef PACK_START struct tagHostCmd_FW_SET_EAPOL {
	FWCmdHdr CmdHdr;
	u16 bAction;
} PACK_END HostCmd_FW_SET_EAPOL, *PHostCmd_FW_SET_EAPOL;

// called to set the hardware back to its pre Scan state
typedef PACK_START struct tagHostCmd_FW_SET_POSTSCAN {
	FWCmdHdr CmdHdr;
	u32 IsIbss;
	u8 BssId[6];
} PACK_END HostCmd_FW_SET_POSTSCAN, *PHostCmd_FW_SET_POSTSCAN;

// Indicate to FW the current state of AP ERP info
typedef PACK_START struct tagHostCmd_FW_SET_G_PROTECT_FLAG {
	FWCmdHdr CmdHdr;
	u32 GProtectFlag;
} PACK_END HostCmd_FW_SET_G_PROTECT_FLAG, *PHostCmd_FW_SET_G_PROTECT_FLAG;

typedef PACK_START struct tagHostCmd_FW_SET_INFRA_MODE {
	FWCmdHdr CmdHdr;
} PACK_END HostCmd_FW_SET_INFRA_MODE, *PHostCmd_FW_SET_INFRA_MODE;

typedef PACK_START struct _HostCmd_FW_GET_WATCHDOG_BITMAP {
	FWCmdHdr CmdHdr;
	u8 Watchdogbitmap;	// for SW/BA
} PACK_END HostCmd_FW_GET_WATCHDOG_BITMAP, *PHostCmd_FW_GET_WATCHDOG_BITMAP;

#define FREQ_BAND_2DOT4GHZ    0x1
#define FREQ_BAND_4DOT9GHZ    0x2
#define FREQ_BAND_5GHZ        0x4
#define FREQ_BAND_5DOT2GHZ    0x8
#define CH_AUTO_WIDTH         0x0
#define CH_10_MHz_WIDTH       0x1
#define CH_20_MHz_WIDTH       0x2
#define CH_40_MHz_WIDTH       0x4
#define CH_80_MHz_WIDTH       0x5
#define CH_160_MHz_WIDTH      0x6
#define CH_5_MHz_WIDTH        0x8
#define EXT_CH_ABOVE_CTRL_CH  0x1
#define EXT_CH_AUTO           0x2
#define EXT_CH_BELOW_CTRL_CH  0x3
#define NO_EXT_CHANNEL        0x0

#define ACT_PRIMARY_CHAN_0  0	/* active primary 1st 20MHz channel */
#define ACT_PRIMARY_CHAN_1  1	/* active primary 2nd 20MHz channel */
#define ACT_PRIMARY_CHAN_2  2	/* active primary 3rd 20MHz channel */
#define ACT_PRIMARY_CHAN_3  3	/* active primary 4th 20MHz channel */
#define ACT_PRIMARY_CHAN_4  4	/* active primary 5th 20MHz channel */
#define ACT_PRIMARY_CHAN_5  5	/* active primary 6th 20MHz channel */
#define ACT_PRIMARY_CHAN_6  6	/* active primary 7th 20MHz channel */
#define ACT_PRIMARY_CHAN_7  7	/* active primary 8th 20MHz channel */

typedef PACK_START struct tagChnFlags11ac {
#ifdef MV_CPU_LE
	u32 FreqBand:6;		//bit0=1: 2.4GHz,bit1=1: 4.9GHz,bit2=1: 5GHz,bit3=1: 5.2GHz,
	u32 ChnlWidth:5;	//bit6=1:10MHz, bit7=1:20MHz, bit8=1:40MHz
	u32 ActPrimary:3;	//000: 1st 20MHz chan, 001:2nd 20MHz chan, 011:3rd 20MHz chan, 100:4th 20MHz chan 
#if defined(SOC_W906X) || defined(SOC_W9068)
	u32 FreqBand2:6;	/* bit0=1: 2.4GHz,bit1=1: 4.9GHz,bit2=1: 5GHz,bit3=1: 5.2GHz */
	u32 ChnlWidth2:5;	/* bit6=1:10MHz, bit7=1:20MHz, bit8=1:40MHz */
	u32 radiomode:3;	/* 0: normal mode, 1: 80+80MHZ, 2: 7+1 or 3+1 */
	u32 isDfsChan:1;
	u32 isDfsChan2:1;
	u32 Reserved:2;
#else
	u32 Reserved:18;
#endif				/* #idfef SOC_W906X */
#else
	union {
		u32 u32_data;
		struct {
#if defined(SOC_W906X) || defined(SOC_W9068)
			u32 Reserved:2;
			u32 isDfsChan2:1;
			u32 isDfsChan:1;
			u32 radiomode:3;	/* 0: normal mode, 1: 80+80MHZ, 2: 7+1 or 3+1 */
			u32 ChnlWidth2:5;	/* bit6=1:10MHz, bit7=1:20MHz, bit8=1:40MHz */
			u32 FreqBand2:6;	/* bit0=1: 2.4GHz,bit1=1: 4.9GHz,bit2=1: 5GHz,bit3=1: 5.2GHz */
#else
			u32 Reserved:18;
#endif				/* #idfef SOC_W906X */
			u32 ActPrimary:3;
			u32 ChnlWidth:5;
			u32 FreqBand:6;
		};
	};
#endif
} CHNL_FLAGS_11AC, *PCHNL_FLAGS_11AC;

typedef PACK_START struct tagChnFlags {
#ifdef MV_CPU_LE
	u32 FreqBand:6;		//bit0=1: 2.4GHz,bit1=1: 4.9GHz,bit2=1: 5GHz,bit3=1: 5.2GHz,
	u32 ChnlWidth:5;	//bit6=1:10MHz, bit7=1:20MHz, bit8=1:40MHz
	u32 ExtChnlOffset:2;	//00: no extension, 01:above, 11:below
#if defined(SOC_W906X) || defined(SOC_W9068)
	u32 FreqBand2:6;	/* bit0=1: 2.4GHz,bit1=1: 4.9GHz,bit2=1: 5GHz,bit3=1: 5.2GHz */
	u32 ChnlWidth2:5;	/* bit6=1:10MHz, bit7=1:20MHz, bit8=1:40MHz */
	u32 radiomode:3;	/* 0: normal mode, 1: 80+80MHZ, 2: 7+1 or 3+1 */
	u32 isDfsChan:1;
	u32 isDfsChan2:1;
	u32 Reserved:3;
#else
	u32 Reserved:19;
#endif				/* #if defined(SOC_W906X) || defined(SOC_W9068) */
#else
	union {
		u32 u32_data;
		struct {
#if defined(SOC_W906X) || defined(SOC_W9068)
			u32 Reserved:3;
			u32 isDfsChan2:1;
			u32 isDfsChan:1;
			u32 radiomode:3;	/* 0: normal mode, 1: 80+80MHZ, 2: 7+1 or 3+1 */
			u32 ChnlWidth2:5;	/* bit6=1:10MHz, bit7=1:20MHz, bit8=1:40MHz */
			u32 FreqBand2:6;	/* bit0=1: 2.4GHz,bit1=1: 4.9GHz,bit2=1: 5GHz,bit3=1: 5.2GHz */
#else
			u32 Reserved:19;
#endif
			u32 ExtChnlOffset:2;
			u32 ChnlWidth:5;
			u32 FreqBand:6;
		};
	};
#endif
} CHNL_FLAGS, *PCHNL_FLAGS;

//          Define data structure for HostCmd_CMD_802_11_RF_CHANNEL
typedef PACK_START struct tagHostCmd_FW_RF_CHANNEL {
	FWCmdHdr CmdHdr;
	u16 Action;
	u8 CurrentChannel;
	CHNL_FLAGS_11AC ChannelFlags;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 Channel2;
#endif
} PACK_END HostCmd_FW_SET_RF_CHANNEL, *PHostCmd_FW_SET_RF_CHANNEL;

typedef PACK_START struct tagHostCmd_FW_SET_RATE {
	//
	//If HT mode is enabled, then HTMCSCodeSet will also contain one MCS code to be used as fixed rate (if applicable).
	//
	FWCmdHdr CmdHdr;
	//u8       DataRateType;   // 0=Auto, Rate Adaption ON, 1=Legacy Fixed,2=HT fixed. No rate adaption
	//u8       RateIndex;     // Used for fixed rate - if fixed, then fill the index with the following condition
	// for LegacyRates, filled with index(0-9)
	//for HT, set RateIndex=0xff
	u8 LegacyRates[RATE_INDEX_MAX_ARRAY];
	u8 HTMCSCodeSet[16];	// Bit map for supported MCS codes.
	//not used as of 11/30/05
	u8 HTBasicMCSCodeSet[16];	// Bit map for supported basic MCS codes.
} PACK_END HostCmd_FW_SET_RATE, *PHostCmd_FW_SET_RATE;

#define FIXED_RATE_WITH_AUTO_RATE_DROP           0
#define FIXED_RATE_WITHOUT_AUTORATE_DROP         1

#define LEGACY_RATE_TYPE                         0
#define HT_RATE_TYPE                             1

#define RETRY_COUNT_VALID                        0
#define RETRY_COUNT_INVALID                      1

typedef PACK_START struct tagFIX_RATE_FLAG {
	// lower rate after the retry count
	u32 FixRateType;	//0: legacy, 1: HT
	u32 RetryCountValid;	//0: retry count is not valid, 1: use retry count specified
} PACK_END FIX_RATE_FLAG, *PFixRateFlag;

typedef PACK_START struct FixRateEntry {
	FIX_RATE_FLAG FixRateTypeFlags;
	u32 FixedRate;		// depending on the flags above, this can be either a legacy rate(not index) or an MCS code.
	u32 RetryCount;
} PACK_END FIXED_RATE_ENTRY;

typedef PACK_START struct tagHostCmd_FW_USE_FIXED_RATE {
	FWCmdHdr CmdHdr;
	u32 Action;
	u32 AllowRateDrop;
	u32 EntryCount;
	FIXED_RATE_ENTRY FixedRateTable[4];
	u8 MulticastRate;
	u8 MultiRateTxType;
	u8 ManagementRate;
} PACK_END HostCmd_FW_USE_FIXED_RATE, *PHostCmd_FW_USE_FIXED_RATE;

typedef PACK_START struct tagUseFixedRateInfo {
	u32 AllowRateDrop;
	u32 EntryCount;
	FIXED_RATE_ENTRY FixedRateTable[4];
} PACK_END USE_FIXED_RATE_INFO, *PUseFixedRateInfo;

typedef PACK_START struct tagGI_TYPE {
#ifdef MV_CPU_LE
	u32 LongGI:1;
	u32 ShortGI:1;
	u32 RESV:30;
#else
	u32 rsvd:6;
	u32 ShortGI:1;
	u32 LongGI:1;
	u32 RESV:24;
#endif
} PACK_END GI_TYPE, *PGIType;

typedef PACK_START struct tagHostCmd_FW_HT_GUARD_INTERVAL {
	FWCmdHdr CmdHdr;
	u32 Action;
	GI_TYPE GIType;
} PACK_END HostCmd_FW_HT_GUARD_INTERVAL, *PHostCmd_FW_HT_GUARD_INTERVAL;

typedef PACK_START struct tagHostCmd_FW_HT_MIMO_CONFIG {
	FWCmdHdr CmdHdr;
	u32 Action;
	u8 RxAntennaMap;
	u8 TxAntennaMap;
} PACK_END HostCmd_FW_HT_MIMO_CONFIG, *PHostCmd_FW_HT_MIMO_CONFIG;

typedef PACK_START struct tagHostCmd_FW_SET_SLOT {
	FWCmdHdr CmdHdr;
	u16 Action;
	u8 Slot;		// Slot=0 if regular, Slot=1 if short.
} PACK_END HostCmd_FW_SET_SLOT, *PHostCmd_FW_SET_SLOT;

//          Define data structures used in HostCmd_CMD_GET_QUEUE_STATS

#define QS_GET_TX_COUNTER           1
#define QS_GET_TX_LATENCY           2
#define QS_GET_RX_LATENCY           3
#define QS_GET_RETRY_HIST           4
#define QS_GET_TX_RATE_HIST         5
#define QS_GET_RX_RATE_HIST         6
#define QS_GET_BA_HIST              7
#define QS_GET_TX_ERROR_INFO        8
#define QS_GET_TX_SCHEDULER_INFO    9

#define NUM_OF_TCQ                 8
#define NUM_OF_RETRY_BIN          64
#define NUM_OF_HW_BA               2
#define QS_MAX_DATA_RATES_G       14
#define QS_MAX_SUPPORTED_MCS      24
#define QS_NUM_SUPPORTED_RATES_G  12
#define QS_NUM_SUPPORTED_MCS      32
#define QS_NUM_SUPPORTED_11N_BW    2
#define QS_NUM_SUPPORTED_GI        2
#define QS_NUM_SUPPORTED_11AC_MCS 10
#define QS_NUM_SUPPORTED_11AC_BW   4
#define QS_NUM_SUPPORTED_11AC_NSS  3
#define QS_NUM_STA_SUPPORTED       4

typedef PACK_START struct _basic_stats_t {
	u32 Min;
	u32 Max;
	u32 Mean;
} PACK_END BASIC_STATS_t;

typedef PACK_START struct _BA_stats_t {
	u32 BarCnt;
	u32 BaRetryCnt;
	u32 BaPktEnqueued;
	u32 BaPktAttempts;
	u32 BaPktSuccess;
	u32 BaPktFailures;
	u32 BaRetryRatio;
} PACK_END BA_STATS_t;

typedef PACK_START struct _SwBA_LfTm_stats_t {
	u32 SBLT_ExpiredCnt;
	u32 SBLT_Retry[63];
} PACK_END SWBA_LFTM_STATS_t;

typedef PACK_START struct _SWBA_STATS_t {
	u32 SwBaPktEnqueued;
	u32 SwBaPktDone;
	u32 SwBaRetryCnt;
	u32 SwBaQNotReadyDrop;
	u32 SwBaQFullDrop;
	u32 SwBaWrongQ;
	u32 SwBaDropNonBa;
	u32 SwBaWrongQid;
	u32 SwBaDropMc;
	u32 SwBaFailHwEnQ;
	u32 pSBLTS;		/* pointer of the record (SWBA_LFTM_STATS_t)in FW */
} PACK_END SWBA_STATS_t;

typedef PACK_START struct _rate_hist_t {
	u8 addr[HostCmd_SIZE_MAC_ADR];
	u16 valid;
	u32 LegacyRates[QS_MAX_DATA_RATES_G];
	u32 HtRates[QS_NUM_SUPPORTED_11N_BW][QS_NUM_SUPPORTED_GI]
		[QS_NUM_SUPPORTED_MCS];
	u32 VHtRates[QS_NUM_SUPPORTED_11AC_NSS][QS_NUM_SUPPORTED_11AC_BW]
		[QS_NUM_SUPPORTED_GI][QS_NUM_SUPPORTED_11AC_MCS];
} PACK_END RATE_HIST_t;

typedef struct _WLAN_RATE_HIST {
	u32 LegacyRates[QS_MAX_DATA_RATES_G];
	u32 HtRates[QS_NUM_SUPPORTED_11N_BW][QS_NUM_SUPPORTED_GI]
		[QS_NUM_SUPPORTED_MCS];
	u32 VHtRates[QS_NUM_SUPPORTED_11AC_NSS][QS_NUM_SUPPORTED_11AC_BW]
		[QS_NUM_SUPPORTED_GI][QS_NUM_SUPPORTED_11AC_MCS];
} WLAN_RATE_HIST;

typedef struct _WLAN_SCHEDULER_HIST {
	u32 Delay[2][5];
	u32 NumAmpdu[2][65];
	u32 NumBytes[2][6];
} WLAN_SCHEDULER_HIST;

#define TX_RATE_HISTO_CUSTOM_CNT            1	//no. of tx rate histogram buffer for custom rate
#define TX_RATE_HISTO_PER_CNT               5
typedef struct _WLAN_TX_RATE_HIST_DATA {
	u32 rateinfo;
	u32 cnt;
	u32 per[TX_RATE_HISTO_PER_CNT];	//store according to TX_HISTO_PER_THRES threshold
} WLAN_TX_RATE_HIST_DATA;

/*SU: Use rate table index as index to update SU_rate. 
* MU: Use rateinfo value because MU rate can be overwritten in fw to make same GI or BW during MU tx
*/
typedef struct _WLAN_TX_RATE_HIST {
	WLAN_TX_RATE_HIST_DATA SU_rate[RATE_ADAPT_MAX_SUPPORTED_RATES];	//follows order of SU rate table index
	WLAN_TX_RATE_HIST_DATA MU_rate[QS_NUM_SUPPORTED_11AC_NSS -
				       1][QS_NUM_SUPPORTED_11AC_BW]
		[QS_NUM_SUPPORTED_GI][QS_NUM_SUPPORTED_11AC_MCS];
	WLAN_TX_RATE_HIST_DATA custom_rate[TX_RATE_HISTO_CUSTOM_CNT];
	u32 CurRateInfo[SU_MU_TYPE_CNT];	//Current rate for 0:SU, 1:MU
	u32 TotalTxCnt[SU_MU_TYPE_CNT];	//Total tx attempt cnt for 0:SU, 1:MU
} WLAN_TX_RATE_HIST;

typedef struct _WLAN_TX_BA_STATS {
	u8 BAHole;		//Total pkt not acked in a BA bitmap
	u8 BAExpected;		//Total Tx pkt expected to be acked
	u8 NoBA;		//No BA is received
	u8 pad;			//Unused
} WLAN_TX_BA_STATS;

typedef struct _WLAN_TX_BA_HIST {
	u16 Stnid;		//Sta id to collect BA stats
	u16 Index;		//Current buffer index
	u8 Type;		//0:SU, 1: MU
	u8 StatsEnable;		//0:disable, 1:enable for BA stats collection
	WLAN_TX_BA_STATS *pBAStats;	//pointer to buffer
} WLAN_TX_BA_HIST;

typedef PACK_START struct _sta_counters_t {
	u8 addr[HostCmd_SIZE_MAC_ADR];
	u16 valid;
	u32 TxAttempts;
	u32 TxSuccesses;
	u32 TxRetrySuccesses;
	u32 TxMultipleRetrySuccesses;
	u32 TxFailures;
} PACK_END STA_COUNTERS_T;

typedef PACK_START struct _rx_sta_counters_t {
	u8 addr[HostCmd_SIZE_MAC_ADR];
	u16 valid;
	u32 rxPktCounts;
} PACK_END RX_STA_COUNTERS_T;

typedef PACK_START struct _qs_counters_t {
	u32 TCQxAttempts[NUM_OF_TCQ];
	u32 TCQxSuccesses[NUM_OF_TCQ];
	u32 TCQxRetrySuccesses[NUM_OF_TCQ];
	u32 TCQxMultipleRetrySuccesses[NUM_OF_TCQ];
	u32 TCQxFailures[NUM_OF_TCQ];
	BASIC_STATS_t TCQxPktRates[NUM_OF_TCQ];
	BA_STATS_t BAxStreamStats[NUM_OF_HW_BA];
	STA_COUNTERS_T StaCounters[QS_NUM_STA_SUPPORTED];
	RX_STA_COUNTERS_T rxStaCounters[QS_NUM_STA_SUPPORTED];
	SWBA_STATS_t SwBAStats[QS_NUM_STA_SUPPORTED];
} PACK_END QS_COUNTERS_t;

typedef PACK_START struct _qs_latency_t {
	BASIC_STATS_t TCQxTotalLatency[NUM_OF_TCQ];
	BASIC_STATS_t TCQxFwLatency[NUM_OF_TCQ];
	BASIC_STATS_t TCQxMacLatency[NUM_OF_TCQ];
	BASIC_STATS_t TCQxMacHwLatency[NUM_OF_TCQ];
	BASIC_STATS_t TCQxQSize[NUM_OF_TCQ];
	BASIC_STATS_t RxFWLatency;
} PACK_END QS_LATENCY_t;

typedef PACK_START struct _qs_retry_hist_t {
	u32 TotalPkts[NUM_OF_TCQ];
	u32 TxPktRetryHistogram[NUM_OF_TCQ];	/* pointer of the record in FW */
} PACK_END QS_RETRY_HIST_t;

typedef PACK_START struct _qs_rate_hist_t {
	u32 duration;
	RATE_HIST_t RateHistoram;
} PACK_END QS_RATE_HIST_t;

typedef PACK_START struct _qs_rx_rate_hist_t {
	u32 duration;
	RATE_HIST_t RateHistoram;
} PACK_END QS_RX_RATE_HIST_t;

typedef PACK_START struct _qs_tx_scheduler_info_t {
	u32 debug_scheduler[12];
	u32 debug_scheduler2[10][3];
	u32 debug_scheduler3[10][3];
	u32 errorcnt[10];
} PACK_END QS_TX_SCHEDULER_INFO_t;

typedef PACK_START struct _queue_stats_t {
	PACK_START union {
#ifdef QUEUE_STATS_LATENCY
		QS_LATENCY_t Latency;
#endif
#ifdef QUEUE_STATS_CNT_HIST
		QS_COUNTERS_t Counters;
		QS_RETRY_HIST_t RetryHist;
		QS_RATE_HIST_t RateHist;
		QS_RX_RATE_HIST_t RxRateHist;
#endif
		QS_TX_SCHEDULER_INFO_t TxScheInfo;
	} qs_u;
} PACK_END QUEUE_STATS_t;

typedef PACK_START struct _HostCmd_GET_QUEUE_STATS {
	FWCmdHdr CmdHdr;
	QUEUE_STATS_t QueueStats;
} PACK_END HostCmd_GET_QUEUE_STATS, *PHostCmd_GET_QUEUE_STATS;

typedef PACK_START struct _HostCmd_QSTATS_SET_SA {
	FWCmdHdr CmdHdr;
	u16 NumOfAddrs;
	u8 Addr[24];
} PACK_END HostCmd_QSTATS_SET_SA, *PHostCmd_QSTATS_SET_SA;

//          Define data structure for HostCmd_CMD_802_11_GET_STAT
typedef PACK_START struct _HostCmd_DS_802_11_GET_STAT {
	FWCmdHdr CmdHdr;
	u32 TxRetrySuccesses;
	u32 TxMultipleRetrySuccesses;
	u32 TxFailures;
	u32 RTSSuccesses;
	u32 RTSFailures;
	u32 AckFailures;
	u32 RxDuplicateFrames;
	u32 RxFCSErrors;	// FCSErrorCount; use same name as stats.h
	u32 TxWatchDogTimeouts;
	u32 RxOverflows;	//used
	u32 RxFragErrors;	//used
	u32 RxMemErrors;	//used
	u32 PointerErrors;	//used
	u32 TxUnderflows;	//used
	u32 TxDone;
	u32 TxDoneBufTryPut;
	u32 TxDoneBufPut;
	u32 Wait4TxBuf;		// Put size of requested buffer in here
	u32 TxAttempts;
	u32 TxSuccesses;
	u32 TxFragments;
	u32 TxMulticasts;
	u32 RxNonCtlPkts;
	u32 RxMulticasts;
	u32 RxUndecryptableFrames;
	u32 RxICVErrors;
	u32 RxExcludedFrames;
	u32 RxWeakIVCount;
	u32 RxUnicasts;
	u32 RxBytes;
	u32 RxErrors;
	u32 RxRTSCount;
	u32 TxCTSCount;
#ifdef MRVL_WAPI
	u32 RxWAPIPNErrors;
	u32 RxWAPIMICErrors;
	u32 RxWAPINoKeyErrors;
	u32 TxWAPINoKeyErrors;
#endif

} PACK_END HostCmd_DS_802_11_GET_STAT, *PHostCmd_DS_802_11_GET_STAT;

//          Define data structure for HostCmd_CMD_MAC_REG_ACCESS
typedef PACK_START struct _HostCmd_DS_MAC_REG_ACCESS {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 Offset;
	u32 Value;
	u16 Reserved;
} PACK_END HostCmd_DS_MAC_REG_ACCESS, *PHostCmd_DS_MAC_REG_ACCESS;

//          Define data structure for HostCmd_DS_MEM_ADDR_ACCESS
typedef PACK_START struct _HostCmd_DS_MEM_ADDR_ACCESS {
	FWCmdHdr CmdHdr;
	u32 Address;
	u16 Length;
	u16 Reserved;
	u32 Value[64];
} PACK_END HostCmd_DS_MEM_ADDR_ACCESS, *PHostCmd_DS_MEM_ADDR_ACCESS;

//          Define data structure for HostCmd_CMD_BBP_REG_ACCESS
typedef PACK_START struct _HostCmd_DS_BBP_REG_ACCESS {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 Offset;
	u8 Value;
	u8 Reserverd[3];
} PACK_END HostCmd_DS_BBP_REG_ACCESS, *PHostCmd_DS_BBP_REG_ACCESS;

//          Define data structure for HostCmd_CMD_RF_REG_ACCESS
typedef PACK_START struct _HostCmd_DS_RF_REG_ACCESS {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 Offset;
	u8 Value;
	u8 Reserverd[3];
} PACK_END HostCmd_DS_RF_REG_ACCESS, *PHostCmd_DS_RF_REG_ACCESS;

#define CLIENT_MODE1 1
#define CLIENT_MODE2 2
typedef PACK_START struct _HostCmd_DS_802_11_BOOST_MODE {
	FWCmdHdr CmdHdr;
	u8 Action;		// 0->get, 1->set
	u8 flag;		// bit 0: 0->unset (Boost mode), 1->set (Non-Boost Mode)
	// bit 1: 0->unset, 1->set (double Boost mode) 
	u8 ClientMode;		// 0 -> mode 1, 1 -> mode 2
} PACK_END HostCmd_DS_802_11_BOOST_MODE, *PHostCmd_DS_802_11_BOOST_MODE;

//          Define data structure for HostCmd_CMD_802_11_RADIO_CONTROL
typedef PACK_START struct _HostCmd_DS_802_11_RADIO_CONTROL {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 Control;		// @bit0: 1/0,on/off, @bit1: 1/0, long/short @bit2: 1/0,auto/fix
	u16 RadioOn;
} PACK_END HostCmd_DS_802_11_RADIO_CONTROL, *PHostCmd_DS_802_11_RADIO_CONTROL;

#define MWL_MAX_TXPOWER_ENTRIES     32
#define TX_POWER_LEVEL_TOTAL        32

#define HAL_TXPWR_ID_CCK                       0
#define HAL_TXPWR_ID_OFDM_HI                   1
#define HAL_TXPWR_ID_OFDM_MED                  2
#define HAL_TXPWR_ID_OFDM_LO                   3
#define HAL_TXPWR_ID_2STREAM_HT20_HI           4
#define HAL_TXPWR_ID_2STREAM_HT20_MED          5
#define HAL_TXPWR_ID_2STREAM_HT20_LO           6
#define HAL_TXPWR_ID_3STREAM_HT20              7
#define HAL_TXPWR_ID_2STREAM_HT40_HI           8
#define HAL_TXPWR_ID_2STREAM_HT40_MED          9
#define HAL_TXPWR_ID_2STREAM_HT40_LO           10
#define HAL_TXPWR_ID_3STREAM_HT40              11
#define HAL_TRPC_ID_2STREAM_HT80_HI            12
#define HAL_TRPC_ID_2STREAM_HT80_MED           13
#define HAL_TRPC_ID_2STREAM_HT80_LO            14
#define HAL_TRPC_ID_3STREAM_HT80               15

//          Define data structure for HostCmd_CMD_802_11_RF_TX_POWER
typedef PACK_START struct _HostCmd_DS_802_11_RF_TX_POWER {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 SupportTxPowerLevel;
	u16 CurrentTxPowerLevel;
	u16 Reserved;
	u16 PowerLevelList[TX_POWER_LEVEL_TOTAL];
} PACK_END HostCmd_DS_802_11_RF_TX_POWER, *PHostCmd_DS_802_11_RF_TX_POWER;
//          Define data structure for HostCmd_CMD_802_11_TX_POWER
typedef struct {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 band;
	u16 ch;
	u16 bw;
	u16 sub_ch;
	u16 PowerLevelList[TX_POWER_LEVEL_TOTAL];
} PACK_END HostCmd_DS_802_11_TX_POWER;
//          Define data structure for HostCmd_CMD_802_11_RF_ANTENNA
typedef PACK_START struct _HostCmd_DS_802_11_RF_ANTENNA {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 AntennaMode;	// Number of antennas or 0xffff(diversity)
} PACK_END HostCmd_DS_802_11_RF_ANTENNA, *PHostCmd_DS_802_11_RF_ANTENNA;

//          Define data structure for HostCmd_CMD_802_11_PS_MODE
typedef PACK_START struct _HostCmd_DS_802_11_PS_MODE {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 PowerMode;		// CAM, Max.PSP or Fast PSP
} PACK_END HostCmd_DS_802_11_PS_MODE, *PHostCmd_DS_802_11_PS_MODE;

#ifdef WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER
typedef PACK_START struct _HostCmd_DS_802_11_COEX_CONF {
	FWCmdHdr CmdHdr;
	u8 reserved;
	u8 enable;
	u8 gpioLevelDetect;
	u8 gpioLevelTrigger;
	u32 gpioReqPin;
	u32 gpioGrantPin;
	u32 gpioPriPin;
} PACK_END HostCmd_DS_802_11_COEX_CONF, *PHostCmd_DS_802_11_COEX_CONF;
#endif

typedef PACK_START struct _HostCmd_DS_802_11_RTS_RETRY {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 Retry;
} PACK_END HostCmd_DS_802_11_RTS_RETRY, *PHostCmd_DS_802_11_RTS_RETRY;

typedef PACK_START struct _HostCmd_DS_802_11_RTS_THSD {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 Threshold;
} PACK_END HostCmd_DS_802_11_RTS_THSD, *PHostCmd_DS_802_11_RTS_THSD;

typedef enum {
	FORCE_PROTECT_NONE,
	FORCE_PROTECT_RTS,
	FORCE_PROTECT_CTS2SELF,
	FORCE_PROTECT_MAX
} FORCE_PROTECT_DEF;

typedef PACK_START struct _HostCmd_PROTECTION_MODE {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 mode;
} PACK_END HostCmd_PROTECTION_MODE, *PHostCmd_PROTECTION_MODE;

// used for stand alone bssid sets/clears
typedef PACK_START struct tagHostCmd_FW_SET_MAC {
	FWCmdHdr CmdHdr;
	u16 MacType;
	u8 MacAddr[6];
} PACK_END HostCmd_DS_SET_MAC, *PHostCmd_DS_SET_MAC,
	HostCmd_FW_SET_BSSID, *PHostCmd_FW_SET_BSSID,
	HostCmd_FW_SET_MAC, *PHostCmd_FW_SET_MAC;

// Indicate to FW to send out PS Poll
typedef struct tagHostCmd_FW_TX_POLL {
	FWCmdHdr CmdHdr;
	u32 PSPoll;
} HostCmd_FW_TX_POLL, *PHostCmd_FW_TX_POLL;

/* Capabilities Field */
typedef struct tagCAPABILITY_FIELD {
#ifdef MV_CPU_LE
	u16 ESS:1;
	u16 IBSS:1;
	u16 CFPollable:1;
	u16 CFPollRequest:1;
	u16 Privacy:1;
	u16 ShortPreamble:1;
	u16 PBCC:1;
	u16 ChannelAgility:1;
	u16 SpectrumMgmt:1;
	u16 QOS:1;
	u16 ShortSlotTime:1;
	u16 Rsvd3:2;
	u16 DSSS_OFDM:1;
	u16 BlockAck:1;
	u16 ExtCaps:1;
#else				//MV_CPU_BE
	u16 ChannelAgility:1;
	u16 PBCC:1;
	u16 ShortPreamble:1;
	u16 Privacy:1;
	u16 CFPollRequest:1;
	u16 CFPollable:1;
	u16 IBSS:1;
	u16 ESS:1;
	u16 ExtCaps:1;
	u16 BlockAck:1;
	u16 DSSS_OFDM:1;
	u16 Rsvd3:2;
	u16 ShortSlotTime:1;
	u16 QOS:1;
	u16 SpectrumMgmt:1;
#endif
} CAPABILITY_FIELD, *PCAPABILITY_FIELD;
// this struct is sent to the firmware for both the start and join
// mlme functions. FW to use these elements to config
typedef PACK_START struct tagHostCmd_FW_SET_BCN_CMD {
	FWCmdHdr CmdHdr;
	u32 CfOffset;
	u32 TimOffset;
	CAPABILITY_FIELD Caps;
	u32 ProbeRspLen;
	u16 BcnPeriod;
	u16 CF_CfpMaxDuration;
	u16 IBSS_AtimWindow;
	u32 StartIbss;		// TRUE=start ibss, FALSE=join ibss
	u8 BssId[6];
	u8 BcnTime[8];
	u8 SsIdLength;
	u8 SsId[32];
	u8 SupportedRates[32];
	u8 DtimPeriod;
	u8 ParamBitMap;		// indicate use of IBSS or CF parameters
	u8 CF_CfpCount;
	u8 CF_CfpPeriod;
	u8 RfChannel;
	u8 AccInterval[8];
	u8 TsfTime[8];
	u8 BeaconFrameLength;
	u8 BeaconBuffer[128];
	u32 GProtection;
} PACK_END HostCmd_FW_SET_BCN_CMD, *PHostCmd_FW_SET_BCN_CMD;

// used for AID sets/clears
typedef PACK_START struct tagHostCmd_FW_SET_AID {
	FWCmdHdr CmdHdr;
	u16 AssocID;
	u8 MacAddr[6];		//AP's Mac Address(BSSID)
	u32 GProtection;
	u8 ApRates[RATE_INDEX_MAX_ARRAY];
} PACK_END HostCmd_FW_SET_AID, *PHostCmd_FW_SET_AID;

typedef PACK_START struct tagHostCmd_FW_SET_NEW_STN {
	FWCmdHdr CmdHdr;
	u16 AID;
	u8 MacAddr[6];
	u16 StnId;
	u16 Action;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 Wds;
	u8 StaMode;
	PeerInfo_t PeerInfo;
	u8 Qosinfo;
	u8 isQosSta:1;
	u8 mfpEnabled:1;
	u8 rsvd:6;
	u32 FwStaPtr;
	IEEEtypes_HT_Element_t HtElem;
	IEEEtypes_VhtCap_t vhtCap;
	u8 maxAmsduSubframes;
#else
	u16 Reserved;
	PeerInfo_t PeerInfo;
	u8 Qosinfo;
	u8 isQosSta;
	u32 FwStaPtr;
	u32 Wds;
	IEEEtypes_HT_Element_t HtElem;
	IEEEtypes_VhtCap_t vhtCap;
#endif				/* SOC_W906X */
} PACK_END HostCmd_FW_SET_NEW_STN, *PHostCmd_FW_SET_NEW_STN;

typedef PACK_START struct tagHostCmd_FW_SET_KEEP_ALIVE_TICK {
	FWCmdHdr CmdHdr;
	u8 tick;

} PACK_END HostCmd_FW_SET_KEEP_ALIVE_TICK, *PHostCmd_FW_SET_KEEP_ALIVE_TICK;

typedef PACK_START struct tagHostCmd_FW_SET_RIFS {
	FWCmdHdr CmdHdr;
	u8 QNum;
} PACK_END HostCmd_FW_SET_RIFS, *PHostCmd_FW_SET_RIFS;

typedef PACK_START struct tagHostCmd_FW_SET_APMODE {
	FWCmdHdr CmdHdr;
	u8 ApMode;
} PACK_END HostCmd_FW_SET_APMODE, *PHostCmd_FW_SET_APMODE;

typedef PACK_START struct tagHostCmd_FW_GET_Parent_TSF {
	FWCmdHdr CmdHdr;
	u16 Action;		// 0 = get only
	u32 ParentTSF;		// lower 4 byte of serving AP's TSF value at time measuring
	//    STA recv beacon or probe response
} PACK_END HostCmd_FW_GET_Parent_TSF, *PHostCmd_FW_GET_Parent_TSF;

typedef PACK_START struct tagHostCmd_CCA_Busy_Fract {
	FWCmdHdr CmdHdr;
	u16 Action;		// 0 = stop, 1 = start
	u16 Reserved;
	u32 CCABusyFrac;	// fraction duration over which CCA indicated channel is busy
#ifdef AP_STEERING_SUPPORT
	u16 StaCnt;
	u8 ChannelUtil;
#endif				//AP_STEERING_SUPPORT
} PACK_END HostCmd_FW_GET_CCA_Busy_Fract, *PHostCmd_FW_GET_CCA_Busy_Fract;

typedef PACK_START struct tagHostCmd_FW_GET_RPI_Density {
	FWCmdHdr CmdHdr;
	u16 Action;		// 0 = stop, 1 = start
	u16 DiffChannel;	// 0 = same channel, 1 = diff channel
	u32 RPI0Density;	// power >= -87
	u32 RPI1Density;	// -82<= power < -87
	u32 RPI2Density;	// -77<= power < -82
	u32 RPI3Density;	// -72<= power < -77
	u32 RPI4Density;	// -67<= power < -72
	u32 RPI5Density;	// -62<= power < -67
	u32 RPI6Density;	// -57<= power < -62
	u32 RPI7Density;	// power < -57

} PACK_END HostCmd_FW_GET_RPI_Density, *PHostCmd_FW_GET_RPI_Density;

typedef PACK_START struct tagHostCmd_FW_GET_NOISE_Level {
	FWCmdHdr CmdHdr;
	u16 Action;		// 0 = get only
	u8 Noise;		//

} PACK_END HostCmd_FW_GET_NOISE_Level, *PHostCmd_FW_GET_NOISE_Level;

//          Define LED control command data structure
#ifdef LED_CONTROL
typedef PACK_START struct tagLEDPattern {
	u8 ucReserved;
	u8 ucPattern;
	u8 ucLEDIndex;
	u8 usState;
} PACK_END LEDPattern, *PLEDPattern;

typedef PACK_START struct tagHostCmd_DS_LED_SET_INFORMATION {
	FWCmdHdr CmdHdr;
	u32 LEDInfoBuf[62];
} PACK_END HostCmd_DS_LED_SET_INFORMATION, *PHostCmd_DS_LED_SET_INFORMATION;

typedef PACK_START struct _HostCmd_Led_Pattern {
	FWCmdHdr CmdHdr;
	u8 Reserved;
	u8 LedPattern;
	u8 LedIndex;
	u8 LedState;
} PACK_END HostCmd_Led_Pattern, *PHostCmd_Led_Pattern;
#define HOSTCMD_LED_AUTO_DEFAULT 0
#define HOSTCMD_LED_CTRL_BY_HOST 1

typedef PACK_START struct tagHostCmd_DS_LED_GET_STATE {
	FWCmdHdr CmdHdr;
	u32 LEDState;
} PACK_END HostCmd_DS_LED_GET_STATE, *PHostCmd_DS_LED_GET_STATE;

typedef PACK_START struct tagHostCmd_DS_LED_SET_STATE {
	FWCmdHdr CmdHdr;
	u32 LEDState;
} PACK_END HostCmd_DS_LED_SET_STATE, *PHostCmd_DS_LED_SET_STATE;
#endif

typedef PACK_START struct _HostCmd_802_11h_Detect_Radar {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 RadarTypeCode;
	u16 MinChirpCount;
	u16 ChirpTimeIntvl;
	u16 PwFilter;
	u16 MinNumRadar;
	u16 PriMinNum;
	u8 EnablePrimary80MHz;
	u8 EnableSecond80MHz;
} PACK_END HostCmd_802_11h_Detect_Radar, *PHostCmd_802_11h_Detect_Radar;

#define DR_DFS_DISABLE                              0
#define DR_CHK_CHANNEL_AVAILABLE_START              1
#define DR_CHK_CHANNEL_AVAILABLE_STOP               2
#define DR_IN_SERVICE_MONITOR_START                 3
#define DR_AUX_SERVICE_START                        4
#define DR_AUX_SERVICE_STOP                         5
#define HostCmd_80211H_RADAR_TYPE_CODE_ETSI_151     151

#define RADIO_MODE_NORMAL   0	// Mode 0 - 20, 40, 80 MHz Mode
#define RADIO_MODE_80p80    1	// Mode 1 - 80 + 80 MHz Mode
#define RADIO_MODE_7x7p1x1  2	// Mode 2 - Scanner (Path A) Mode (20, 40, 80 MHz on other paths)

enum {
	DFS_MAIN,
	DFS_AUX,
	DFS_ALL,
	MAX_DFS_NUM = DFS_ALL
};

typedef PACK_START struct _HostCmd_STOP_Beacon {
	FWCmdHdr CmdHdr;
} PACK_END HostCmd_STOP_Beacon, *PHostCmd_STOP_Beacon;

#define INTF_AP_MODE     0
#define INTF_STA_MODE    1

typedef PACK_START struct tagBSS_START {
	FWCmdHdr CmdHdr;
	u32 Enable;		/* FALSE: Disable or TRUE: Enable */
	u8 Amsdu;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 IntfFlag;
	u8 qosEnabled;		//0: disabled, 1: enabled
	u8 Rsvd[1];
	u32 Status;
	u8 MacAddr[6];
	u8 NumOfBasicRates;
	u8 BasicRate[IEEEtypes_MAX_DATA_RATES];
	u8 nonQosMcBcFlag;	//0: disabled, 1: enabled
#endif
} PACK_END HostCmd_BSS_START, *PHostCmd_BSS_START;

typedef PACK_START struct tagHostCmd_AP_Beacon {
	FWCmdHdr CmdHdr;
	IEEEtypes_StartCmd_t StartCmd;
	IEEEtypes_RSN_IE_WPAMixedMode_t thisStaRsnMixedIE;
} PACK_END HostCmd_AP_Beacon, *PHostCmd_AP_Beacon;

typedef PACK_START struct tagHost_Cmd_Update_TIM {
	u16 Aid;
	u32 Set;
} PACK_END HostCmd_Update_TIM, *PHostCmd_Update_TIM;

typedef PACK_START struct tagHost_CMD_UpdateTIM {
	FWCmdHdr CmdHdr;
	HostCmd_Update_TIM UpdateTIM;
} PACK_END HostCmd_UpdateTIM, *PHostCmd_UpdateTIM;

typedef struct tagHostCmd_SSID_BROADCAST {
	FWCmdHdr CmdHdr;
	u32 SsidBroadcastEnable;
} HostCmd_SSID_BROADCAST, *PHostCmd_SSID_BROADCAST;

typedef struct tagHostCmd_WDS {
	FWCmdHdr CmdHdr;
	u32 WdsEnable;
} HostCmd_WDS, *PHostCmd_WDS;

typedef PACK_START struct tagBURST_MODE {
	FWCmdHdr CmdHdr;
	u32 Enable;		//0 -- Disbale. or 1 -- Enable.
} PACK_END HostCmd_BURST_MODE, *PHostCmd_BURST_MODE;

typedef struct _DomainChannelEntry {
	u8 FirstChannelNo;
	u8 NoofChannel;
	u8 MaxTransmitPw;
} PACK_END DomainChannelEntry;

typedef PACK_START struct _DomainCountryInfo {
	u8 CountryString[3];
	u8 GChannelLen;
	DomainChannelEntry DomainEntryG[MaxMultiDomainCapabilityEntryG];
								      /** Assume only 1 G zone **/
	u8 AChannelLen;
	DomainChannelEntry DomainEntryA[MaxMultiDomainCapabilityEntryA];
								      /** Assume max of 5 A zone **/
} PACK_END DomainCountryInfo;

typedef PACK_START struct _HostCmd_SET_SWITCH_CHANNEL {
	FWCmdHdr CmdHdr;
	u32 Next11hChannel;
	u32 Mode;
	u32 InitialCount;
	CHNL_FLAGS_11AC ChannelFlags;
	u32 NextHTExtChnlOffset;	/*HT Ext Channel offset    */
	u32 dfs_test_mode;	/* DFS test bypasses channel switch on CSA countdown. */
	u32 Channel2;
} PACK_END HostCmd_SET_SWITCH_CHANNEL, *PHostCmd_SET_SWITCH_CHANNEL;

typedef PACK_START struct _HostCmd_SET_SPECTRUM_MGMT {
	FWCmdHdr CmdHdr;
	u32 SpectrumMgmt;	// 0 disable, 1 enable
} PACK_END HostCmd_SET_SPECTRUM_MGMT, *PHostCmd_SET_SPECTRUM_MGMT;

typedef PACK_START struct _HostCmd_SET_POWER_CONSTRAINT {
	FWCmdHdr CmdHdr;
	s32 PowerConstraint;	// local maximum txpower constraint
	IEEEtypes_VHTTransmitPowerEnvelopeElement_t
		VHTTransmitPowerEnvelopeElement;
} PACK_END HostCmd_SET_POWER_CONSTRAINT, *PHostCmd_SET_POWER_CONSTRAINT;

typedef PACK_START struct _HostCmd_SET_COUNTRY_INFO {
	FWCmdHdr CmdHdr;
	u32 Action;		// 0 -> get, 1 ->set  2->del
	DomainCountryInfo DomainInfo;
} PACK_END HostCmd_SET_COUNTRY_INFO, *PHostCmd_SET_COUNTRY_INFO;

typedef PACK_START struct _HostCmd_SET_REGIONCODE_INFO {
	FWCmdHdr CmdHdr;
	u16 regionCode;
} PACK_END HostCmd_SET_REGIONCODE_INFO, *PHostCmd_SET_REGIONCODE_INFO;

#define WSC_BEACON_IE           0
#define WSC_PROBE_RESP_IE       1
typedef PACK_START struct _HostCmd_SET_WSC_IE {
	FWCmdHdr CmdHdr;
	u16 ieType;
	WSC_COMB_IE_t wscIE;
} PACK_END HostCmd_SET_WSC_IE, *PHostCmd_SET_WSC_IE;

typedef PACK_START struct tagHostCmd_FW_SET_WTP_MODE {
	FWCmdHdr CmdHdr;
	u8 enabled;
} PACK_END HostCmd_FW_SET_WTP_MODE, *PHostCmd_FW_SET_WTP_MODE;

#ifdef MRVL_WAPI
#define WAPI_BEACON_IE           0
#define WAPI_PROBE_RESP_IE       1
typedef PACK_START struct _HostCmd_SET_WAPI_IE {
	FWCmdHdr CmdHdr;
	u16 ieType;
	WAPI_COMB_IE_t WAPIIE;
} PACK_END HostCmd_SET_WAPI_IE, *PHostCmd_SET_WAPI_IE;
#endif

// for HostCmd_CMD_SET_WMM_MODE
typedef struct tagHostCmd_FW_SetWMMMode {
	FWCmdHdr CmdHdr;
	u16 Action;		// 0->unset, 1->set
} HostCmd_FW_SetWMMMode, *PHostCmd_FW_SetWMMMode;

#if defined(SOC_W906X) || defined(SOC_W9068)
typedef struct _Generic_Beacon {
	u16 beacon_buf_size;
	u16 rsvd;
	u8 *ht_cap;
	u8 *ht_op;
	u8 *ht_op_i_comp;
	u8 *ht_op_b_comp;
	u8 *vht_cap;
	HE_Capabilities_IE_t *he_cap;
	HE_Operation_IE_t *he_op;
	MU_EDCA_param_set_t *mu_edca;
	u8 beacon_buf[MAX_BEACON_SIZE];
} Generic_Beacon;
#endif

typedef struct tagHostCmd_FW_SetIEs {
	FWCmdHdr CmdHdr;
	u16 Action;		// 0->get, 1->set, 2->del
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 beacon_buf[MAX_BEACON_SIZE];
#else
	u16 IeListLenHT;
	u16 IeListLenVHT;
	u16 IeListLenProprietary;
	/*Buffer size same as Generic_Beacon */
	u8 IeListHT[148];
	u8 IeListVHT[24];
	u8 IeListProprietary[112];
#endif
} HostCmd_FW_SetIEs, *PHostCmd_FW_SetIEs;

typedef PACK_START struct tagHostCmd_FW_SET_MAX_DELAY_BY_AC {
	FWCmdHdr CmdHdr;
	u8 action;		//0-set, 1-get;
	u8 ac;
	u32 maxTolerableDelay;
} PACK_END HostCmd_FW_SET_MAX_DELAY_BY_AC, *PHostCmd_FW_SET_MAX_DELAY_BY_AC;

#define EDCA_PARAM_SIZE                18
#define BA_PARAM_SIZE                  2

typedef PACK_START struct tagHostCmd_FW_SET_EDCA_PARAMS {
	FWCmdHdr CmdHdr;
	u16 Action;		//0 = get all, 0x1 =set CWMin/Max,  0x2 = set TXOP , 0x4 =set AIFSN
	u16 TxOP;		// in unit of 32 us
	u32 CWMax;		// 0~15
	u32 CWMin;		// 0~15
	u8 AIFSN;
	u8 TxQNum;		// Tx Queue number.
} PACK_END HostCmd_FW_SET_EDCA_PARAMS, *PHostCmd_FW_SET_EDCA_PARAMS;

typedef PACK_START struct tagHostCmd_FW_SET_MEDIUM_TIME {
	FWCmdHdr CmdHdr;
	u16 UserPriority;	// User Priority to set
	u16 MediumTime;		// in unit of 32 us
} PACK_END HostCmd_FW_SET_MEDIUM_TIME, *PHostCmd_FW_SET_MEDIUM_TIME;

typedef PACK_START struct tagHostCmd_FW_SET_BA_PARAMS {
	FWCmdHdr CmdHdr;
	u8 BaAction;
	u8 Reserved;
	u8 BAparams[BA_PARAM_SIZE];
} PACK_END HostCmd_FW_SET_BA_PARAMS, *PHostCmd_FW_SET_BA_PARAMS;

typedef PACK_START struct tagHostCmd_FW_SET_HCCA {
	FWCmdHdr CmdHdr;
	u32 ulQoSMode;
	u8 CFPollable;
	u8 CFPollrequest;
	u8 APSD;
	u8 QueueRequest;
	u8 TxOpRequest;
} PACK_END HostCmd_FW_SET_HCCA, *PHostCmd_FW_SET_HCCA;

typedef PACK_START struct tagHostCmd_FW_SET_CFP {
	FWCmdHdr CmdHdr;
	u8 CFPCount;
	u8 CFPPeriod;
	u16 CFPMaxDuration;
	u16 CFPDurRemaining;
	u32 DTIMPeriod;
} PACK_END HostCmd_FW_SET_CFP, *PHostCmd_FW_SET_CFP;

#ifdef POWERSAVE_OFFLOAD
/** This cmmand will be send by driver to f/w whenever each bss has powersave station cnt going from
0> 1 and also when PS number goes to 0, f/w (as per normal) before queuing MC/BC traffic will check this
count before deciding whether to queue to the respective depth in the MC/BC queue **/
typedef PACK_START struct tagHostCmd_SET_POWERSAVESTATION {
	FWCmdHdr CmdHdr;
	u8 NumberofPowersave;	   /** No of active powersave station **/
	u8 reserved;
} PACK_END HostCmd_SET_POWERSAVESTATION, *PHostCmd_SET_POWERSAVESTATION;
/** this command will be send by the driver to f/w whenever driver detect that a station is going to
powersave and there is packet pending for the station.  This command is also use with the GET TIM command
to reset the TIM when there is no packet for the station or the station has gone out of powersave.  F/W will update
the tim on the next tbtt **/
typedef PACK_START struct tagHostCmd_SET_TIM {
	FWCmdHdr CmdHdr;
	u16 Aid;
	u32 Set;
	u8 reserved;
} PACK_END HostCmd_SET_TIM, *PHostCmd_SET_TIM;

/** this command will return the TIM buffer of the respective BSS to the driver **/
typedef PACK_START struct taghost_CMD_GET_TIM {
	FWCmdHdr CmdHdr;
	u8 TrafficMap[251];
	u8 reserved;
} PACK_END HostCmd_GET_TIM, *PHostCmd_GET_TIM;
#endif

/******************************************************************************
@HWENCR@
Hardware Encryption related data structures and constant definitions.
Note that all related changes are marked with the @HWENCR@ tag.
*******************************************************************************/

#if defined(SOC_W906X) || defined(SOC_W9068)
#define MAX_ENCR_KEY_LENGTH                 16	/* max 128 bits - depends on type */
#define WAPI_KEY_LENGTH                     16	/* WAPI key size */
#define KEY_LENGTH_256_BITS                 32	/* 256 bits key length */
#define MIC_KEY_LENGTH                      8	/* size of Tx/Rx MIC key - 8 bytes */
#define PN_LENGTH                           8	/* size of Tx/Rx MIC key - 8 bytes */
#define WAPI_PN_LENGTH                      16	/* size of Tx/Rx MIC key - 8 bytes */

#define KEY_TYPE_ID_NONE                    0x00	/* Key type is WEP        */
#define KEY_TYPE_ID_WEP                     0x01	/* Key type is WEP        */
#define KEY_TYPE_ID_TKIP                    0x02	/* Key type is TKIP        */
#define KEY_TYPE_ID_CCMP                    0x03	/* Key type is AES-CCMP-128    */
#define KEY_TYPE_ID_WAPI                    0x04	/* Key type is WAPI    */
#define KEY_TYPE_ID_GCMP                    0x05	/* Key type is AES-CCMP-256    */
#define KEY_TYPE_ID_CMAC                    0x06	/* Key type is IGTK CMAC    */
#define KEY_TYPE_ID_GMAC                    0x07	/* Key type is IGTK GMAC    */

/* flags used in structure - same as driver EKF_XXX flags */
#define ENCR_KEY_FLAG_INUSE                 BIT(0)	/* indicate key is in use */
#define ENCR_KEY_FLAG_GTK_RX_KEY            BIT(1)	/* Group key for RX only */
#define ENCR_KEY_FLAG_GTK_TX_KEY            BIT(2)	/* Group key for TX */
#define ENCR_KEY_FLAG_PTK                   BIT(3)	/* pairwise */
#define ENCR_KEY_FLAG_RXONLY                BIT(4)	/* only used for RX */
#define ENCR_KEY_FLAG_IGTK_RX_KEY           BIT(5)	/* IGTK key for Rx */
#define ENCR_KEY_FLAG_IGTK_TX_KEY           BIT(6)	/* IGTK key for Tx */
#define ENCR_KEY_FLAG_WEP_TXKEY             BIT(7)	/* Tx key for WEP */
#define ENCR_KEY_FLAG_MICKEY_VALID          BIT(8)	/* Tx/Rx MIC keys are valid */
#define ENCR_KEY_FLAG_TSC_VALID             BIT(9)	/* Sequence counters are valid */
#define ENCR_KEY_FLAG_STA_MODE              BIT(10)	/* station mode */
#else
#define MAX_ENCR_KEY_LENGTH						16	/* max 128 bits - depends on type */
#define KEY_LENGTH_256_BITS						32	/* 256 bits key length */
#define MIC_KEY_LENGTH							8	/* size of Tx/Rx MIC key - 8 bytes */

#define KEY_TYPE_ID_WEP							0x00	/* Key type is WEP              */
#define KEY_TYPE_ID_TKIP						0x01	/* Key type is TKIP             */
#define KEY_TYPE_ID_AES							0x02	/* Key type is AES-CCMP */
#define KEY_TYPE_ID_CCMP						0x02
#ifdef MRVL_WAPI
#define KEY_TYPE_ID_WAPI 						0x03	/* Key type is WAPI     */
#endif
#define KEY_TYPE_ID_CCMP_256                    0x04
#define KEY_TYPE_ID_GCMP_128                    0x05
#define KEY_TYPE_ID_GCMP_256                    0x06

/* flags used in structure - same as driver EKF_XXX flags */
#define ENCR_KEY_FLAG_INUSE						0x00000001	/* indicate key is in use */
#define ENCR_KEY_FLAG_RXGROUPKEY				0x00000002	/* Group key for RX only */
#define ENCR_KEY_FLAG_TXGROUPKEY				0x00000004	/* Group key for TX */
#define ENCR_KEY_FLAG_PAIRWISE					0x00000008	/* pairwise */
#define ENCR_KEY_FLAG_RXONLY					0x00000010	/* only used for RX */
// These flags are new additions - for hardware encryption commands only.
#define ENCR_KEY_FLAG_AUTHENTICATOR				0x00000020	/* Key is for Authenticator */
#define ENCR_KEY_FLAG_TSC_VALID					0x00000040	/* Sequence counters are valid */
#define ENCR_KEY_FLAG_WEP_TXKEY					0x01000000	/* Tx key for WEP */
#define ENCR_KEY_FLAG_MICKEY_VALID				0x02000000	/* Tx/Rx MIC keys are valid */

#endif /* SOC_W906X */

#define CIPHER_OUI_TYPE_NONE                    0x00
#define CIPHER_OUI_TYPE_TKIP                    0x02
#define CIPHER_OUI_TYPE_CCMP                    0x04
#define CIPHER_OUI_TYPE_GCMP                    0x08
#define CIPHER_OUI_TYPE_CCMP_256                0x09
#define CIPHER_OUI_TYPE_GCMP_256                0x0a

typedef enum tagENCR_TYPE {
	EncrTypeWep = 0,
	EncrTypeDisable = 1,
	EncrTypeTkip = 4,
	EncrTypeAes = 6,
	EncrTypeCcmp128 = EncrTypeAes,
	EncrTypeMix = 7,
	EncrTypeWapi = 8,
	EncrTypeCcmp256 = 9,
	EncrTypeGcmp128 = 10,
	EncrTypeGcmp256 = 11,
	EncrTypeAesOnly = 255,
} ENCR_TYPE;

#if !defined(SOC_W906X) && !defined(SOC_W9068)
/*
UPDATE_ENCRYPTION command action type.
*/
typedef enum tagENCR_ACTION_TYPE {
	// request to enable/disable HW encryption
	EncrActionEnableHWEncryption,
	// request to set encryption key
	EncrActionTypeSetKey,
	// request to remove one or more keys
	EncrActionTypeRemoveKey,
	EncrActionTypeSetGroupKey,
} ENCR_ACTION_TYPE;
#endif

/*
Key material definitions (for WEP, TKIP, AES-CCMP, WAPI)
*/

/* 
WEP Key material definition
----------------------------
WEPKey    --> An array of 'MAX_ENCR_KEY_LENGTH' bytes.
Note that we do not support 152bit WEP keys
*/
typedef PACK_START struct _WEP_TYPE_KEY {
	// WEP key material (max 128bit)
	u8 KeyMaterial[MAX_ENCR_KEY_LENGTH];
} PACK_END WEP_TYPE_KEY, *PWEP_TYPE_KEY;

/*
TKIP Key material definition
----------------------------
This structure defines TKIP key material. Note that
the TxMicKey and RxMicKey may or may not be valid.
*/
/* TKIP Sequence counter - 24 bits */
/* Incremented on each fragment MPDU */
typedef PACK_START struct tagENCR_TKIPSEQCNT {
	u16 low;
	u32 high;
} PACK_END ENCR_SEQCNT, *PENCR_SEQCNT, ENCR_TKIPSEQCNT, *PENCR_TKIPSEQCNT;

typedef PACK_START struct _TKIP_TYPE_KEY {
	// TKIP Key material. Key type (group or pairwise key) is determined by flags 
	// in KEY_PARAM_SET structure.
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 PN[PN_LENGTH];
#endif
	u8 KeyMaterial[MAX_ENCR_KEY_LENGTH];
	// MIC keys
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 TxMicKey[MIC_KEY_LENGTH];
	u8 RxMicKey[MIC_KEY_LENGTH];
	ENCR_SEQCNT Rsc;
	ENCR_SEQCNT Tsc;
#else
	u8 TkipTxMicKey[MIC_KEY_LENGTH];
	u8 TkipRxMicKey[MIC_KEY_LENGTH];
	ENCR_TKIPSEQCNT TkipRsc;
	ENCR_TKIPSEQCNT TkipTsc;
#endif
} PACK_END TKIP_TYPE_KEY, *PTKIP_TYPE_KEY;

/*
AES-CCMP Key material definition
--------------------------------
This structure defines AES-CCMP key material.
*/
typedef PACK_START struct _AES_TYPE_KEY {
	// AES Key material, support gcmp256/ccmp256/ccmp128/gcmp128
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 PN[PN_LENGTH];
#endif
	u8 KeyMaterial[KEY_LENGTH_256_BITS];
} PACK_END AES_TYPE_KEY, *PAES_TYPE_KEY;

typedef PACK_START struct _WAPI_TYPE_KEY {
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 PN[WAPI_PN_LENGTH];
#endif
	u8 KeyMaterial[MAX_ENCR_KEY_LENGTH];
	u8 MicKeyMaterial[MAX_ENCR_KEY_LENGTH];
} PACK_END WAPI_TYPE_KEY, *PWAPI_TYPE_KEY;

#if !defined(SOC_W906X) && !defined(SOC_W9068)
/*
Encryption key definition.
--------------------------
This structure provides all required/essential
information about the key being set/removed.
*/
typedef PACK_START struct _KEY_PARAM_SET {
	// Total length of this structure (Key is variable size array)
	u16 Length;
	// Key type - WEP, TKIP or AES-CCMP.
	// See definitions above
	u16 KeyTypeId;
	// key flags (ENCR_KEY_FLAG_XXX_
	u32 KeyInfo;
	// For WEP only - actual key index
	u32 KeyIndex;
	// Size of the key
	u16 KeyLen;
	// Key material (variable size array)
#ifdef MRVL_WAPI
	u16 Reserved;
#endif
	PACK_START union {
		WEP_TYPE_KEY WepKey;
		TKIP_TYPE_KEY TkipKey;
		AES_TYPE_KEY AesKey;
#ifdef MRVL_WAPI
		WAPI_TYPE_KEY WapiKey;
#endif
	} PACK_END Key;
	u8 Macaddr[6];
} PACK_END KEY_PARAM_SET, *PKEY_PARAM_SET;
#endif
/*
HostCmd_FW_UPDATE_ENCRYPTION_KEY
----------------------------
Define data structure for updating firmware encryption keys.

*/
#if defined(SOC_W906X) || defined(SOC_W9068)
typedef PACK_START struct tagHostCmd_FW_ENCRYPTION_SET_KEY {
	// standard command header
	FWCmdHdr CmdHdr;
	// Action - see ACT_GET/ACT_SET/ACT_DEL
	u16 Action;
	u8 Macaddr[6];
	u8 KeyType;
	u8 KeyIndex;
	u16 KeyLen;
	u32 KeyInfo;
	//
	PACK_START union {
		WEP_TYPE_KEY Wep;
		TKIP_TYPE_KEY Tkip;
		AES_TYPE_KEY Aes;
		WAPI_TYPE_KEY Wapi;
	} PACK_END Key;

} PACK_END HostCmd_FW_UPDATE_SECURITY_KEY, *PHostCmd_FW_UPDATE_SECURITY_KEY;
#else
typedef PACK_START struct tagHostCmd_FW_ENCRYPTION {
	// standard command header
	FWCmdHdr CmdHdr;
	// Action type - see ENCR_ACTION_TYPE
	u32 ActionType;		// ENCR_ACTION_TYPE
	// size of the data buffer attached.
	u32 DataLength;
	// data buffer - maps to one KEY_PARAM_SET structure
	//KEY_PARAM_SET Key;
	u8 macaddr[6];
	u8 ActionData[1];
} PACK_END HostCmd_FW_UPDATE_ENCRYPTION, *PHostCmd_FW_UPDATE_ENCRYPTION;

typedef PACK_START struct tagHostCmd_FW_ENCRYPTION_SET_KEY {
	// standard command header
	FWCmdHdr CmdHdr;
	// Action type - see ENCR_ACTION_TYPE
	u32 ActionType;		// ENCR_ACTION_TYPE
	// size of the data buffer attached.
	u32 DataLength;
	// data buffer - maps to one KEY_PARAM_SET structure
	KEY_PARAM_SET KeyParam;
} PACK_END HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY,
	*PHostCmd_FW_UPDATE_ENCRYPTION_SET_KEY;
#endif /* SOC_W906X */
//Superfly rate Info structure
#define LEGACY_FORMAT       0
#define HT_FORMAT           1

#define SHORT_GI            1
#define STANDARD_GI         0

#define BW_20MHZ            0
#define BW_40MHZ            1

#define NO_ADV_CODING       0
#define LDPC_ADV_CODING     1
#define RS_ADV_CODING       2
#define RESV_ADV_CODING     3

#define ANT_SELECT_A        1
#define ANT_SELECT_B        2
#define ANT_SELECT_2BY2     3
#define ANT_SELECT_2BY3     0

#define LOWER_ACT_SUBCH     0x00
#define UPPER_ACT_SUBCH     0x01
#define BOTH_SUBCH          0x02

#define HC_LONG_PREAMBLE    0
#define HC_SHORT_PREAMBLE   1

#define ENABLE_TEST_RATE            1
#define DISABLE_TEST_RATE           0
#define AUTO_RATE_DROP_TABLE_SIZE   4

typedef struct RateInfo_t {
	u16 Format:1;		//0 = Legacy format, 1 = Hi-throughput format
	u16 ShortGI:1;		//0 = Use standard guard interval,1 = Use short guard interval
	u16 Bandwidth:1;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel
	u16 RateIDMCS:6;	//= RateID[3:0]; Legacy format,= MCS[5:0]; HT format
	u16 AdvCoding:2;	//AdvCoding 0 = No AdvCoding,1 = LDPC,2 = RS,3 = Reserved
	u16 AntSelect:2;	//Bitmap to select one of the transmit antennae
	u16 ActSubChan:2;	//Active subchannel for 40 MHz mode 00:lower, 01= upper, 10= both on lower and upper
	u16 Preambletype:1;	//Preambletype 0= Long, 1= Short;

} PACK_END RateInfo_t1;

//Superfly rate change structure
typedef struct Rate_Change_t {
	RateInfo_t1 RateInfo;	//Superfly rate info 
	u16 Reserved1:8;
	u16 Count:4;
	u16 Reserved2:3;
	u16 DropFrame:1;
} PACK_END Rate_Change_t1;

typedef struct tagRATE_TABLE_INFO {
	u32 EnableTestRate;
	u32 AllowRateDrop;	// use fixed rate specified but firmware can drop to 
	u32 TotalRetryCount;
	Rate_Change_t1 FixedAutoRateDropTable[AUTO_RATE_DROP_TABLE_SIZE];

} PACK_END RATE_TABLE_INFO_t, *PRATE_TABLE_INFO_t;

typedef struct tagHostCmd_FW_SET_TEST_RATE_TABLE {
	FWCmdHdr CmdHdr;
	u32 Action;
	//HostCmd_ACT_GEN_GET                        0x0000
	//HostCmd_ACT_GEN_SET                        0x0001                                     
	RATE_TABLE_INFO_t RateTableInfo;
} PACK_END HostCmd_FW_SET_TEST_RATE_TABLE, *PHostCmd_FW_SET_TEST_RATE_TABLE;

/******************************************************************************
@STADB@
Station information database related data structures and constant definitions.
Note that all related changes are marked with the @STADB@ tag.
*******************************************************************************/

//
// Reason codes - defines the reason why an entry is added/deleted or updated.
//                  May be useful for debugging purposes?
#define STABD_REASON_NEW_ENTRY              0x00000001
#define STABD_REASON_CONNECTION_TORN        0x00000002
#define STABD_REASON_PEER_INACTIVE          0x00000003
#define STABD_REASON_PEER_ACTIVE            0x00000004
#define STABD_REASON_PEER_CONFIG_CHANGE     0x00000005

// flags for the legacy rates.
#define RATE_INFO_FLAG_BASIC_RATE           BIT(1)
#define RATE_INFO_FLAG_OFDM_RATE            BIT(2)
typedef PACK_START struct tagRateInfo {
	// Rate flags - see above.
	u32 Flags;
	// Rate in 500Kbps units.
	u8 RateKbps;
	// 802.11 rate to conversion table index value.
	// This is the value required by the firmware/hardware.
	u16 RateCodeToIndex;
} PACK_END RATE_INFO, *PRATE_INFO;

/*
UPDATE_STADB command action type.
*/
typedef PACK_START enum tagSTADB_ACTION_TYPE {
	// request to add entry to stainfo db
	StaInfoDbActionAddEntry,
	// request to modify peer entry
	StaInfoDbActionModifyEntry,
	// request to remove peer from stainfo db
	StaInfoDbActionRemoveEntry
} PACK_END STADB_ACTION_TYPE;

// Peer Entry flags - used to define the charasticts of the peer node.
#define PEER_TYPE_ACCESSPOINT               BIT(1)
#define PEER_TYPE_ADHOC_STATION             BIT(2)

#define PEER_CAPABILITY_HT_CAPABLE_EWC      BIT(1)

/**
* PEER_CAPABILITY_INFO - Datastructure to store peer capability information.
*/

typedef PACK_START struct tagHostCmd_FW_SET_LOOPBACK_MODE {
	FWCmdHdr CmdHdr;
	u8 Enable;
	// 0 = Disable loopback mode
	// 1 = Enable loopback mode
} PACK_END HostCmd_FW_SET_LOOPBACK_MODE, *PHostCmd_FW_SET_LOOPBACK_MODE;

/*
@11E-BA@
802.11e/WMM Related command(s)/data structures
*/

typedef PACK_START struct tagBAStreamFlags {
#ifdef MV_CPU_LE
	u32 BaType:2;
	u32 BaDirection:3;
	u32 Reserved:24;
#else
	u32 rsv:4;
	u32 BaDirection:3;
	u32 BaType:1;
	u32 Reserved:20;
#endif
} PACK_END BASTREAM_FLAGS;

// Flag to indicate if the stream is an immediate block ack stream.
// if this bit is not set, the stream is delayed block ack stream.
#define BASTREAM_FLAG_DELAYED_TYPE            0
#define BASTREAM_FLAG_IMMEDIATE_TYPE          1

// Flag to indicate the direction of the stream (upstream/downstream).
// If this bit is not set, the direction is downstream.
#define BASTREAM_FLAG_DIRECTION_UPSTREAM      0
#define BASTREAM_FLAG_DIRECTION_DOWNSTREAM    1
#define BASTREAM_FLAG_DIRECTION_DLP           2
#define BASTREAM_FLAG_DIRECTION_BOTH          3

typedef enum tagBaActionType {
	BaCreateStream,
	BaUpdateStream,
	BaDestroyStream,
	BaFlushStream,
	BaCheckCreateStream
} BASTREAM_ACTION_TYPE;

typedef PACK_START struct tagBaContext {
	u32 Context;
} PACK_END BASTREAM_CONTEXT;

// parameters for block ack creation
typedef PACK_START struct tagCreateBaParams {
	// BA Creation flags - see above
	BASTREAM_FLAGS Flags;
	// idle threshold
	u32 IdleThrs;
	// block ack transmit threshold (after how many pkts should we send BAR?)
	u32 BarThrs;
	// receiver window size
	u32 WindowSize;
	// MAC Address of the BA partner
	u8 PeerMacAddr[6];
	// Dialog Token
	u8 DialogToken;
	//TID for the traffic stream in this BA
	u8 Tid;
	// shared memory queue ID (not sure if this is required)
	u8 QueueId;
	u8 ParamInfo;
	// returned by firmware - firmware context pointer.
	// this context pointer will be passed to firmware for all future commands.
	BASTREAM_CONTEXT FwBaContext;
	u8 ResetSeqNo;		     /** 0 or 1**/
	u16 CurrentSeq;
	u32 vhtrxfactor;
	u8 StaSrcMacAddr[6];	/* This is for virtual station in Sta proxy mode */
} PACK_END BASTREAM_CREATE_STREAM;

// new transmit sequence number information
typedef PACK_START struct tagBaUpdateSeqNum {
	// BA flags - see above
	BASTREAM_FLAGS Flags;
	// returned by firmware in the create ba stream response
	BASTREAM_CONTEXT FwBaContext;
	// new sequence number for this block ack stream
	u16 BaSeqNum;
} PACK_END BASTREAM_UPDATE_STREAM;

typedef PACK_START struct tagBaStreamContext {
	// BA Stream flags
	BASTREAM_FLAGS Flags;
	// returned by firmware in the create ba stream response
	BASTREAM_CONTEXT FwBaContext;
	u8 Tid;
	u8 PeerMacAddr[6];
} PACK_END BASTREAM_STREAM_INFO;

//Command to create/destroy block ACK
typedef PACK_START struct tagHostCmd_FW_BASTREAM {
	FWCmdHdr CmdHdr;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u16 ActionType;
	u16 staid;
#else
	u32 ActionType;
#endif
	PACK_START union {
		// information required to create BA Stream...
		BASTREAM_CREATE_STREAM CreateParams;
		// update starting/new sequence number etc.
		BASTREAM_UPDATE_STREAM UpdtSeqNum;
		// destroy an existing stream...
		BASTREAM_STREAM_INFO DestroyParams;
		// destroy an existing stream...
		BASTREAM_STREAM_INFO FlushParams;
	} PACK_END BaInfo;
} PACK_END HostCmd_FW_BASTREAM, *PHostCmd_FW_BASTREAM;

typedef PACK_START struct tagHostCmd_GET_SEQNO {
	FWCmdHdr CmdHdr;
	u8 MacAddr[6];
	u8 TID;
	u16 SeqNo;
	u8 reserved;
} PACK_END HostCmd_GET_SEQNO, *PHostCmd_GET_SEQNO;

#ifdef NDIS_MINIPORT_DRIVER
#pragma pack()
#endif

//
//*************************************************************
//*************************************************************
//*************************************************************
//
//
//
// Driver only
//
//   For diagnostic test purposes
//
#ifdef NDIS_MINIPORT_DRIVER

#define HostCmd_CMD_DUTY_CYCLE_TEST                0x002A
#define HostCmd_RET_DUTY_CYCLE_TEST                0x802A
#pragma pack(1)

/*  Define data structure for HostCmd_CMD_DUTY_CYCLE_TEST */
typedef struct _HostCmd_DS_DUTY_CYCLE_TEST {
	FWCmdHdr CmdHdr;
	u16 Action;
	u32 BeaconOffsetInSQ;
	u32 RFParam;		//Replace beaconFrame[2] with RFParam
	u16 Reserved;

} HostCmd_DS_DUTY_CYCLE_TEST, *PHostCmd_DS_DUTY_CYCLE_TEST;

typedef struct _BSS_DESCRIPTION_SET_ALL_FIELDS {
	u8 BSSID[EAGLE_ETH_ADDR_LEN];
	u8 SSID[EAGLE_MAX_SSID_LENGTH];
	u8 BSSType;
	u16 BeaconPeriod;
	u8 DTIMPeriod;
	u8 TimeStamp[8];
	u8 LocalTime[8];
	IEEEtypes_PhyParamSet_t PhyParamSet;
	IEEEtypes_SsParamSet_t SsParamSet;
	IEEEtypes_CapInfo_t Cap;
	u8 DataRates[RATE_INDEX_MAX_ARRAY];
	u8 Pad[5];
} BSS_DESCRIPTION_SET_ALL_FIELDS, *PBSS_DESCRIPTION_SET_ALL_FIELDS;

typedef struct _BSS_DESCRIPTION_SET_FIXED_FIELDS {
	u8 BSSID[EAGLE_ETH_ADDR_LEN];
	u8 SSID[EAGLE_MAX_SSID_LENGTH];
	u8 BSSType;
	u16 BeaconPeriod;
	u8 DTIMPeriod;
	u8 TimeStamp[8];
	u8 LocalTime[8];
} BSS_DESCRIPTION_SET_FIXED_FIELDS, *PBSS_DESCRIPTION_SET_FIXED_FIELDS;
#pragma pack()
#endif //NDIS_MINIPORT_DRIVER

//          Define data structure for HostCmd_CMD_SET_REGION_POWER
typedef PACK_START struct _HostCmd_DS_SET_REGION_POWER {
	FWCmdHdr CmdHdr;
	u16 MaxPowerLevel;
	u16 Reserved;
} PACK_END HostCmd_DS_SET_REGION_POWER, *PHostCmd_DS_SET_REGION_POWER;
//          Define data structure for HostCmd_CMD_SET_RATE_ADAPT_MODE
typedef PACK_START struct _HostCmd_DS_SET_RATE_ADAPT_MODE {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 RateAdaptMode;
} PACK_END HostCmd_DS_SET_RATE_ADAPT_MODE, *PHostCmd_DS_SET_RATE_ADAPT_MODE;

//          Define data structure for HostCmd_CMD_SET_LINKADAPT_CS_MODE
typedef PACK_START struct _HostCmd_DS_SET_LINKADAPT_CS_MODE {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 CSMode;
} PACK_END HostCmd_DS_SET_LINKADAPT_CS_MODE, *PHostCmd_DS_SET_LINKADAPT_CS_MODE;

typedef PACK_START struct tagHostCmd_FW_SET_N_PROTECT_FLAG {
	FWCmdHdr CmdHdr;
	u32 NProtectFlag;
} PACK_END HostCmd_FW_SET_N_PROTECT_FLAG, *PHostCmd_FW_SET_N_PROTECT_FLAG;

typedef PACK_START struct tagHostCmd_FW_SET_N_PROTECT_OPMODE {
	FWCmdHdr CmdHdr;
	u8 NProtectOpMode;
} PACK_END HostCmd_FW_SET_N_PROTECT_OPMODE, *PHostCmd_FW_SET_N_PROTECT_OPMODE;

typedef PACK_START struct tagHostCmd_FW_SET_ACNT_STOP {
	FWCmdHdr CmdHdr;
} PACK_END HostCmd_FW_SET_ACNT_STOP, *PHostCmd_FW_SET_ACNT_STOP;

typedef PACK_START struct tagHostCmd_FW_SET_OPTIMIZATION_LEVEL {
	FWCmdHdr CmdHdr;
	u8 OptLevel;
} PACK_END HostCmd_FW_SET_OPTIMIZATION_LEVEL,
	*PHostCmd_FW_SET_OPTIMIZATION_LEVEL;

#define CAL_TBL_SIZE        160
typedef PACK_START struct tagHostCmd_FW_GET_CALTABLE {
	FWCmdHdr CmdHdr;
	u8 annex;
	u8 index;
	u8 len;
	u8 Reserverd;
	u8 calTbl[CAL_TBL_SIZE];
} PACK_END HostCmd_FW_GET_CALTABLE, *PHostCmd_FW_GET_CALTABLE;
typedef PACK_START struct tagHostCmd_FW_SET_MIMOPSHT {
	FWCmdHdr CmdHdr;
	u8 Addr[6];
	u8 Enable;
	u8 Mode;
} PACK_END HostCmd_FW_SET_MIMOPSHT, *PHostCmd_FW_SET_MIMOPSHT;

typedef PACK_START struct tagHostCmd_FW_GET_BEACON {
	FWCmdHdr CmdHdr;
	u16 Bcnlen;
	u8 Reserverd[2];
	u8 Bcn[MAX_BEACON_SIZE];
} PACK_END HostCmd_FW_GET_BEACON, *PHostCmd_FW_GET_BEACON;

typedef PACK_START struct _HostCmd_SET_RXPATHOPT {
	FWCmdHdr CmdHdr;
	u32 RxPathOpt;
	u32 RxPktThreshold;
} PACK_END HostCmd_SET_RXPATHOPT, *PHostCmd_SET_RXPATHOPT;

typedef PACK_START struct tagHostCmd_DWDS_ENABLE {
	FWCmdHdr CmdHdr;
	u32 Enable;		//0 -- Disbale. or 1 -- Enable.

} PACK_END HostCmd_DWDS_ENABLE, *PHostCmd_DWDS_ENABLE;

typedef PACK_START struct tagHostCmd_FW_FLUSH_TIMER {
	FWCmdHdr CmdHdr;
	u32 value;		//0 -- Disbale; >0 holds time value in usecs.
} PACK_END HostCmd_FW_FLUSH_TIMER, *PHostCmd_FW_FLUSH_TIMER;

#define RATE_TBL_SIZE    100
typedef PACK_START struct tagHostCmd_FW_GET_RATETABLE {
	FWCmdHdr CmdHdr;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u16 staid;
#else
	u8 Addr[6];
#endif
	u8 Type;		//0: SU, 1: MU    
	u32 SortedRatesIndexMap[2 * RATE_ADAPT_MAX_SUPPORTED_RATES];	//Multiply 2 because 2 DWORD in rate info
} PACK_END HostCmd_FW_GET_RATETABLE, *PHostCmd_FW_GET_RATETABLE;

typedef PACK_START struct tagHostCmd_FW_SET_RATETABLE {
	FWCmdHdr CmdHdr;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u16 staid;
#else
	u8 Addr[6];
#endif
	u32 Action;
	u32 Rateinfo;
} PACK_END HostCmd_FW_SET_RATETABLE, *PHostCmd_FW_SET_RATETABLE;

typedef PACK_START struct tagHostCmd_FW_HT_GF_MODE {
	FWCmdHdr CmdHdr;
	u32 Action;
	u32 Mode;
} PACK_END HostCmd_FW_HT_GF_MODE, *PHostCmd_FW_HT_GF_MODE;

typedef PACK_START struct tagHostCmd_FW_HT_STBC_MODE {
	FWCmdHdr CmdHdr;
	u32 Action;
	u32 Mode;
} PACK_END HostCmd_FW_HT_STBC_MODE, *PHostCmd_FW_HT_STBC_MODE,
	*PHostCmd_FW_HT_STBC_TX;

typedef PACK_START struct tagHostCmd_FW_SET_11N_20_40_SWITCHING {
	FWCmdHdr CmdHdr;
	u8 AddChannel;
} PACK_END HostCmd_FW_SET_11N_20_40_SWITCHING,
	*PHostCmd_FW_SET_11N_20_40_SWITCHING;

typedef PACK_START struct tagHostCmd_FW_HT_BF_MODE {
	FWCmdHdr CmdHdr;
	u8 option;
	u8 csi_steering;
	u8 mcsfeedback;
	u8 mode;       /**  NDPA or control wrapper **/
	u8 interval;
	u8 slp;
	u8 power;
} PACK_END HostCmd_FW_HT_BF_MODE, *PHostCmd_FW_HT_BF_MODE;
typedef PACK_START struct tagHostCmd_FW_OFDMA_MODE {
	FWCmdHdr CmdHdr;
	u8 option;
	u8 ru_mode;
	u8 max_sta;	  /**  NDPA or control wrapper **/
	u8 rsvd;
	u32 max_delay;
} PACK_END HostCmd_FW_OFDMA_MODE, *PHostCmd_FW_OFDMA_MODE;

typedef PACK_START struct tagHostCmd_FW_SET_NOACK {
	FWCmdHdr CmdHdr;
	u8 Enable;
	u8 be_enable;
	u8 bk_enable;
	u8 vi_enable;
	u8 vo_enable;
} PACK_END HostCmd_FW_SET_NOACK, *PHostCmd_FW_SET_NOACK;

typedef PACK_START struct tagHostCmd_FW_RC_CAL {
	FWCmdHdr CmdHdr;
	u32 rc_cal[4][2];
} PACK_END HostCmd_FW_RC_CAL, *PHostCmd_FW_RC_CAL;

typedef PACK_START struct tagHostCmd_FW_TEMP {
	FWCmdHdr CmdHdr;
	u32 temp;
} PACK_END HostCmd_FW_TEMP, *PHostCmd_FW_TEMP;

typedef PACK_START struct tagHostCmd_PHY_BW {
	FWCmdHdr CmdHdr;
	u32 PHY_BW;
} PACK_END HostCmd_PHY_BW, *PHostCmd_PHY_BW;

typedef PACK_START struct tagHostCmd_ALPHA_TIMING_FC {
	FWCmdHdr CmdHdr;
	u32 Enable;
	int Fc_Value;
} PACK_END HostCmd_ALPHA_TIMING_FC, *PHostCmd_ALPHA_TIMING_FC;

typedef PACK_START struct tagHostCmd_FW_SET_NOSTEER {
	FWCmdHdr CmdHdr;
	u8 Enable;
} PACK_END HostCmd_FW_SET_NOSTEER, *PHostCmd_FW_SET_NOSTEER;

typedef PACK_START struct tagHostCmd_FW_SET_CDD {
	FWCmdHdr CmdHdr;
	u32 Enable;
} PACK_END HostCmd_FW_SET_CDD, *PHostCmd_FW_SET_CDD;
typedef PACK_START struct tagHostCmd_FW_SET_TXHOP {
	FWCmdHdr CmdHdr;
	u8 Enable;
	u8 Txhopstatus;
} PACK_END HostCmd_FW_SET_TXHOP, *PHostCmd_FW_SET_TXHOP;

typedef PACK_START struct tagHostCmd_FW_HT_BF_TYPE {
	FWCmdHdr CmdHdr;
	u32 Action;
	u32 Mode;
} PACK_END HostCmd_FW_HT_BF_TYPE, *PHostCmd_FW_HT_BF_TYPE;

typedef PACK_START struct ssu_cmd_s {
	u32 Nskip;		//0~3
	u32 Nsel;		//0~3
	u32 AdcDownSample;	//0~3
	u32 MaskAdcPacket;	//[0,1]
	u32 Output16bits;	//[0,1]
	u32 PowerEnable;	//[0,1]
	u32 RateDeduction;	//[0,1]
	u32 PacketAvg;		//0~7
	u32 Time;		//msec
	u32 TestMode;		//0: SC3 format. 1: new format
	u32 FFT_length;
	u32 ADC_length;
	u32 RecordLength;
	u32 BufferBaseAddress;
	u32 BufferBaseSize;
	u32 BufferNumbers;
	u32 BufferSize;
	u32 ProcTime;		//usec 
} PACK_END ssu_cmd_t;

typedef PACK_START struct tagHostCmd_FW_SET_SPECTRAL_ANALYSIS {
	FWCmdHdr CmdHdr;
	u32 Action;
	ssu_cmd_t ssu;
} PACK_END HostCmd_FW_SET_SPECTRAL_ANALYSIS_TYPE,
	*PHostCmd_FW_SET_SPECTRAL_ANALYSIS_TYPE;

typedef PACK_START struct tagHostCmd_FW_SET_BW_SIGNALLING {
	FWCmdHdr CmdHdr;
	u32 Action;
	u32 Mode;		//0: disable, 1: static, 2: dynamic
	u8 Bitmap;
} PACK_END HostCmd_FW_SET_BW_SIGNALLING, *PHostCmd_FW_SET_BW_SIGNALLING;

typedef PACK_START struct tagHostCmd_FW_GET_CONSEC_TXFAIL_ADDR {
	FWCmdHdr CmdHdr;
	u8 Addr[6];
} PACK_END HostCmd_FW_GET_CONSEC_TXFAIL_ADDR,
	*PHostCmd_FW_GET_CONSEC_TXFAIL_ADDR;

typedef PACK_START struct tagHostCmd_FW_TXFAILLIMIT {
	FWCmdHdr CmdHdr;
	u32 txfaillimit;
} PACK_END HostCmd_FW_TXFAILLIMIT, *PHostCmd_FW_TXFAILLIMIT;

typedef PACK_START struct tagHostCmd_FW_VHT_OP_MODE {
	FWCmdHdr CmdHdr;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u16 staid;
#else
	u8 Addr[6];
#endif
	u8 vht_NewRxChannelWidth;
	u8 vht_NewRxNss;
} PACK_END HostCmd_FW_VHT_OP_MODE, *PHostCmd_FW_VHT_OP_MODE;

typedef PACK_START struct tagHostCmd_FW_LED_CTRL {
	FWCmdHdr CmdHdr;
	u8 led_on;
} PACK_END HostCmd_FW_LED_CTRL, *PHostCmd_FW_LED_CTRL;
typedef PACK_START struct tagHostCmd_FW_NEWDP_CTRL {
	FWCmdHdr CmdHdr;
	u8 ch, width, rates, rate_type, rate_bw, rate_gi, rate_ss;
} PACK_END HostCmd_FW_NEWDP_CTRL, *PHostCmd_FW_NEWDP_CTRL;

typedef PACK_START struct tagHostCmd_FW_NEWDP_RATEDROP {
	FWCmdHdr CmdHdr;
	u32 enabled;
	u32 rate_index;
	u32 sta_index;

} PACK_END HostCmd_FW_NEWDP_RATEDROP, *PHostCmd_FW_NEWDP_RATEDROP;

typedef PACK_START struct tagHostCmd_FW_FIXED_PE {
	FWCmdHdr CmdHdr;
	u32 enabled;
	u8 pe;
} PACK_END HostCmd_FW_FIXED_PE, *PHostCmd_FW_FIXED_PE;

#if defined(SOC_W906X) || defined(SOC_W9068)
typedef enum {
	OFFCHAN_IDLE = 0,	//An offchan can only be processed when it's currently OFFCHAN_IDLE.
	OFFCHAN_STARTED,	//An offchan req is successfully delivered to FW
	OFFCHAN_CH_CHANGE,	//It is on off-channel currently
	OFFCHAN_DONE,		//DRV-only state, current offchan req is done, it is on service channel currently.
	OFFCHAN_COOLDOWN,	//DRV-only state, after a offchan req is done, we wait for a cool-down time. Then we process the next req.
	OFFCHAN_WAIT4_BCNDONE,	//PFW-only state, wait for BcnDone (before change channel)
	OFFCHAN_WAIT4_TXSTOPPED,	//PFW-only state, wait for tx-stopped (before change channel)
	OFFCHAN_TXSTOPPED,	//PFW-only state, tx is stopped (before change channel)
	OFFCHAN_WAIT4_DWELL,	//PFW-only state, if rx-type, wait for dwell done (after change channel)
	OFFCHAN_WAIT4_TXDONE,	//PFW-only state, if tx-type, wait for txDone (after change channel)
} offchan_status;
#else //906X off-channel
typedef enum {
	OFFCHAN_FAIL = 0,
	OFFCHAN_DONE,
	OFFCHAN_CH_CHANGE,
	OFFCHAN_TIMEOUT,
	OFFCHAN_STARTED,
	OFFCHAN_PENDING,
} offchan_status;
#endif //906X off-channel
typedef enum {
	OFFCHAN_TYPE_RX = 0,
	OFFCHAN_TYPE_TX,
	OFFCHAN_TYPE_RX_NF,
	OFFCHAN_TYPE_SENSORD,
} offchan_req_type;

//This structure size has to be same as dot11_offchan_req_t
typedef PACK_START struct tag_dot11_offchan_req {
	u32 id;			//unique for each request, for application tracking
	u32 channel;		//every request
	u32 lifetime;		//lifetime for request wait
	u32 start_ts;		//start timestamp-need to be synced with host        todo.. should be pointing to Timestamp
	u32 dwell_time;		//sensord/ RRM Rx duration
	u32 channel_width;	//RRM Rx
	union {
		void *pak;	//NDP, RC            todo.. should be pointing to Packet
		u32 pak_ptr[2];	//void * is 8 bytes in drv, 4 bytes in fw
	};
	u8 radio_slot;		//radio for request
	u8 req_type;		//RRM Rx or Tx or sensord
	u8 priority;		//P1, P2-RRM Rx, P3, NDP, P4 RC
	u8 status;		//status of request    
	u32 primary;		//for hal_cfg_data.act_primary
	u32 sub;		//for hal_cfg_data.act_sub
} PACK_END DOT11_OFFCHAN_REQ_t, *PDOT11_OFFCHAN_REQ;

typedef union {
	struct {
		u8 DA[6];
		u8 SA[6];
	};
	struct {
		u16 RateCode;
		u8 pad[6];
		u32 Callback;	/* Used for Packet returned to Firmware */
	};
} tx_DA_SA_t;

//This structure size has to be same as  _wltxdesc_t
typedef PACK_START struct tag_dot11_offchan_txdesc {
	tx_DA_SA_t u;
	u32 Ctrl;
	u32 Data;
	u32 User;
} PACK_END DOT11_OFFCHAN_TXDESC_t, *PDOT11_OFFCHAN_TXDESC;

#define MAX_OFF_CHAN_PKT_SIZE	2048
typedef PACK_START struct tagHostCmd_FW_OFFCHANNEL {
	FWCmdHdr CmdHdr;
	DOT11_OFFCHAN_REQ_t OffChannel;
	u8 Data[MAX_OFF_CHAN_PKT_SIZE];
} PACK_END HostCmd_FW_NEWDP_OFFCHANNEL, *PHostCmd_FW_NEWDP_OFFCHANNEL;

typedef PACK_START struct tagHostCmd_FW_OFFCHANNEL_DBG {
	FWCmdHdr CmdHdr;
	u32 offchan_state;
} PACK_END HostCmd_FW_NEWDP_OFFCHANNEL_DBG, *PHostCmd_FW_NEWDP_OFFCHANNEL_DBG;

#define DFS_GET_ALL                         0
#define DFS_SET_FCC_MIN_RADAR_NUM_PRI       1
#define DFS_SET_ETSI_MIN_RADAR_NUM_PRI      2
#define DFS_SET_JPN_W53_MIN_RADAR_NUM_PRI   3
#define DFS_SET_JPN_W56_MIN_RADAR_NUM_PRI   4
#define DFS_SET_FALSE_DETECT_TH             5
#define DFS_SET_FCC_ZC_ERROR_TH             6
#define DFS_SET_ETSI_ZC_ERROR_TH            7
#define DFS_SET_JP_ZC_ERROR_TH              8

typedef PACK_START struct tagHostCmd_FW_DFS_PARAMS {
	FWCmdHdr CmdHdr;
	u16 Action;
	u8 fcc_min_radar_num_pri[8];
	u8 etsi_min_radar_num_pri[8];
	u8 jpn_w53_min_radar_num_pri[8];
	u8 jpn_w56_min_radar_num_pri[8];
	u8 false_detect_th;
	u8 fcc_zc_error_th;
	u8 etsi_zc_error_th;
	u8 jp_zc_error_th;
} PACK_END HostCmd_FW_DFS_PARAMS, *PHostCmd_FW_DFS_PARAMS;

#define MAX_OFF_CHAN_REQ        32
#define MAX_OFF_CHAN_DONE       128

typedef struct {
	DOT11_OFFCHAN_REQ_t OffChannel;
	DOT11_OFFCHAN_TXDESC_t txDesc;
} offchan_desc_t;

typedef struct {
	u32 id;
	u32 status;
} offchan_done_stat_t;

typedef PACK_START struct tagHostCmd_FW_OFFCHANNEL_START {
	FWCmdHdr CmdHdr;
	u32 OffChanReqBase;
	u32 OffChanDoneBase;
	u32 OffChanReqHead;
	u32 OffChanReqTail;
	u32 OffChanDoneHead;
	u32 OffChanDoneTail;
	u32 pPhyoffchanshared;
} PACK_END HostCmd_FW_NEWDP_OFFCHANNEL_START,
	*PHostCmd_FW_NEWDP_OFFCHANNEL_START;

enum {
	ServiceChan = 0,
	OffChanTxDwells = 1,
	PromRxOnlyDwells = 2,
};
typedef PACK_START struct _PROM_CNF_t {
	// Promiscuous Mode Configuration
	u8 CnfType;		//ServiceChan,OffChanTxDwells, PromRxOnlyDwells 
	u16 PromDataMask;	// SubType Mask for Forwarding Promisc Data
	u16 PromDataTrunc;	// Size for Forwarding Promisc Data
	u16 PromMgmtMask;	// SubType Mask for Forwarding Promisc Mgmt
	u16 PromMgmtTrunc;	// Size for Forwarding Promisc Mgmt
	u16 PromCtrlMask;	// SubType Mask for Forwarding Promisc Ctrl
	u16 PromCtrlTrunc;	// Size for Forwarding Promisc Ctrl
	u16 PromRsvdMask;	// SubType Mask for Forwarding Promisc Rsvd
	u16 PromRsvdTrunc;	// Size for Forwarding Promisc Rsvd
	u32 PromPolNomWin;	// Policer: Window Size for bursting (TU)
	u32 PromPolNomPkts;	// Policer: kpps limit (Packets/64TU ~= 15pps)
} PACK_END PROM_CNF_t, *pPROM_CNF_t;

typedef PACK_START struct tagHostCmd_FW_PROM_CNF {
	FWCmdHdr CmdHdr;
	PROM_CNF_t PromCnf;
} PACK_END HostCmd_FW_NEWDP_PROM_CNF, *PHostCmd_FW_NEWDP_PROM_CNF;

typedef struct tagHostCmd_FW_SET_ACNT_BUF_SIZE {
	FWCmdHdr CmdHdr;
#if defined(SOC_W906X) || defined(SOC_W9068) || defined(NEWDP_ACNT_CHUNKS)
	u32 Action;
	u32 log2Chunk;
	u32 acntBufBase[ACNT_NCHUNK];
#else
	u32 acntBufBase;
#endif
	u32 acntBufSize;
} HostCmd_FW_SET_ACNT_BUF_SIZE, *PHostCmd_FW_SET_ACNT_BUF_SIZE;
typedef struct radio_status_s {
	u32 dead:1;
	u32 dumping:1;
	u32 enabled:1;
	u32 SI_init:1;
	u32 DFS_required:1;
	u32 rsv0:27;
	u32 TimeSinceEnabled;
	u32 rsv2;
} radio_status_t;

typedef struct drv_fw_shared_s {
	u32 dfs_freg;
	radio_status_t RadioStatus;
} drv_fw_shared_t;

typedef struct offchan_shared_s {
	u32 OffChanDoneHead;
	u32 OffChanDoneTail;
} offchan_shared_t;

typedef PACK_START struct tagHostCmd_FW_OFFCHANNEL_PWR {
	FWCmdHdr CmdHdr;
	s8 Pwr;
	u8 AntBitMap;
	u8 Channel;
} PACK_END HostCmd_FW_NEWDP_OFFCHANNEL_PWR, *PHostCmd_FW_NEWDP_OFFCHANNEL_PWR;

#define SENSORD_NSIKEY_LEN    16
typedef PACK_START struct sensord_init_s {
	u32 ca_mailbox;
	u32 sage_addr;
	u32 buff_addr;
	u32 buff_size;
	u32 freq_list;
	int num_freq;
	u32 instance;
	u32 mvl_radio_id;
	unsigned char enableSI;
	unsigned char nsiKey[SENSORD_NSIKEY_LEN];
} PACK_END sensord_init_t;

typedef struct sensord_init_ext_s {
	sensord_init_t SensordInit;
	u32 mrvl_pri_mailbox;	//Points to drv & fw shared memory of structure drv_fw_shared_t
} sensord_init_ext_t;

typedef PACK_START struct tagHostCmd_FW_SENSORD_INIT {
	FWCmdHdr CmdHdr;
	u8 Action;		//0: To pass only shared mem to fw , 1: to pass sensord param and shared mem
	sensord_init_ext_t SensordInit_ext;
} PACK_END HostCmd_FW_NEWDP_SENSORD_INIT, *PHostCmd_FW_NEWDP_SENSORD_INIT;

typedef PACK_START struct tagHostCmd_FW_NEWDP_SENSORD_CMD {
	FWCmdHdr CmdHdr;
} PACK_END HostCmd_FW_NEWDP_SENSORD_CMD, *PHostCmd_FW_NEWDP_SENSORD_CMD;

typedef PACK_START struct {
	union {
		u8 key[16];
		u16 rk[8];
	 /*CKIP*/};
} PACK_END key_entry_t;

typedef PACK_START struct {
	u8 keytype;
#define  KEYTYPE_NONE       0
#define  KEYTYPE_WEP        1
#define  KEYTYPE_TKIP       2
#define  KEYTYPE_CCMP       3
#define  KEYTYPE_CKIP       4
	u8 keysubtype;
#define  KEYSUBTYPE_11W     1
	u8 keylen;
	u8 vlan;		/* vlan=0..15, or 0xFF to disable */
	u8 iv3;
	union {
		struct {	/* TKIP MIC info */
			u8 txmic[8];
			u8 rxmic[8];
		} tkip;
		/* possible ccmp256 -- 32 bytes -- in the future? */
		struct {
			u16 tsc_lo16;	/* read back tsc */
			u32 tsc_hi32;
		} readback;
	} u;
} PACK_END rx_mcast_key_info_t;

typedef PACK_START struct {
	key_entry_t keyp;
	rx_mcast_key_info_t info;
} PACK_END Key_t;

typedef PACK_START struct {	// Receive Multicast Group
	u8 RA[6];		// Multicast L2 Address
	u16 Index;		// Index into Mcast Database (programmed from Host)
	Key_t Keys[4];		// Keys defined for this Rx Multicast Stream
} PACK_END rx_mcast_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_SET_RX_MCAST {
	FWCmdHdr CmdHdr;
	rx_mcast_t RxMcast;
} PACK_END HostCmd_FW_NEWDP_SET_RX_MCAST, *PHostCmd_FW_NEWDP_SET_RX_MCAST;

typedef PACK_START struct tagHostCmd_FW_NEWDP_SENSORD_SET_BLANKING {
	FWCmdHdr CmdHdr;
	u8 blankingmask;
} PACK_END HostCmd_FW_NEWDP_SENSORD_SET_BLANKING,
	*PHostCmd_FW_NEWDP_SENSORD_SET_BLANKING;

typedef PACK_START struct bfmr_config_s {
	u16 chan;
	u8 bw;
	u8 rx_ant;
	u8 tx_ant;
	u8 ht_cap[28];
	u8 addr[6];
	u8 flags;
	u8 vht_cap_data[12];
} PACK_END bfmr_config_t;

typedef struct BFMR_init_status_s {
	u8 chan_init;
	u8 bw_init;
	u8 rx_ant_init;
	u8 tx_ant_init;
	u8 ht_cap_init;
	u8 addr_init;
	u8 vht_cap_init;
	u8 rsv1;
} BFMR_init_status_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_BFMR_CONFIG {
	FWCmdHdr CmdHdr;
	u8 Action;		//0: Only use ht_cap, vht_cap_data, flags from BFMRconfig , 1: use all setting from BFMRconfig
	bfmr_config_t BFMRconfig;
} PACK_END HostCmd_FW_NEWDP_BFMR_CONFIG, *PHostCmd_FW_NEWDP_BFMR_CONFIG;

typedef struct wlcfg_sbf_open_s {
	//reassign =1, reassign CurrentStaMAc's slot to ReassignedStaMac
	//reassign =0, allocate slot for CurrentStaMac , ignore ReassignedStaMac
	u8 CurrentStaMac[6];
	u8 ReassignStaMac[6];
	u8 reassign;
	u8 rsv1;
	u16 rsv2;
} wlcfg_sbf_open_t;

typedef PACK_START struct bfmr_sbf_open_s {
	u8 sbf_slot;
	u8 addr[6];
	u8 ht_cap[28];
	u8 rate_map;
	u8 vht_cap_data[12];
} PACK_END bfmr_sbf_open_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_BFMR_SBF_OPEN {
	FWCmdHdr CmdHdr;
	bfmr_sbf_open_t BFMRsbfOpen;
} PACK_END HostCmd_FW_NEWDP_BFMR_SBF_OPEN, *PHostCmd_FW_NEWDP_BFMR_SBF_OPEN;

typedef struct wlcfg_sbf_close_s {
	u8 StaMac[6];
	u16 rsv1;
} wlcfg_sbf_close_t;

typedef PACK_START struct bfmr_sbf_close_s {
	u8 sbf_slot;
	u8 rsv1;
	u16 rsv2;
} PACK_END bfmr_sbf_close_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_BFMR_SBF_CLOSE {
	FWCmdHdr CmdHdr;
	bfmr_sbf_close_t BFMRsbfClose;
} PACK_END HostCmd_FW_NEWDP_BFMR_SBF_CLOSE, *PHostCmd_FW_NEWDP_BFMR_SBF_CLOSE;

#if defined(SOC_W906X) || defined(SOC_W9068)
#define MAX_RATE_POWER_ENTRY    1420
typedef PACK_START struct rate_power_W906x_s {
	u8 format:2;		// 0:legecy, 1:HT, 2:VHT, 3:HE
	u8 STBC:1;		// 0:off, 1:on
	u8 BF:1;		// 0:off, 1:on
	u8 sigBW:2;		// 0:ht20, 1:ht40, 2:ht80, 3:ht160 or 80p80
	u8 resvd:2;

	u16 mcs:6;		//
	u16 NSS:3;		// 0:1SS, 1:2SS, 2:3SS, 3:4SS..., 7:8SS
	u16 rsvd1:7;

	u8 Active_Tx;		// Tx antenna bitmap

	u16 Power_pri:11;	//Power for primary channel. dBm.s11.4 format
	u16 rsvd2:5;

	u16 Power_2nd:11;	//Power for secondary channel.dBm.s11.4 format
	u16 rsvd3:5;
} PACK_END rate_power_W906x_t;

typedef PACK_START struct rate_power_table_s {
	u8 channel;
	u8 rsvd;
	u16 NumOfEntry;		//number of valid entry in array RatePower
	u32 rsvd1;
	u64 RatePower[MAX_RATE_POWER_ENTRY];
} PACK_END rate_power_table_t;

typedef PACK_START struct Info_rate_power_table_s {
	u32 DrvCnt;
	u32 FwCnt;
	rate_power_table_t RatePwrTbl;
} PACK_END Info_rate_power_table_t;

//dralee++
typedef PACK_START struct cmd_rate_power_table_s {
	u32 addr;		//to save phy addr from drv in cmd_proc
	Info_rate_power_table_t pwrtable;	//to save dma content   
} PACK_END cmd_rate_power_table_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_SET_POWER_PER_RATE {
	FWCmdHdr CmdHdr;
	u16 offset:15;
	u16 last:1;
	u8 payload[0];
} PACK_END HostCmd_FW_NEWDP_SET_POWER_PER_RATE,
	*PHostCmd_FW_NEWDP_SET_POWER_PER_RATE;

#else
//W8964
#define MAX_RATE_POWER_ENTRY    512
typedef struct rate_power_s {
	u8 format:2;		// 0:legecy, 1:HT, 2:VHT
	u8 STBC:1;		// 0:off, 1:on
	u8 BF:1;		// 0:off, 1:on
	u8 sigBW:2;		// 0:ht20, 1:ht40, 2:ht80, 3:ht160
	u8 resvd:2;
	u8 mcs:6;		//
	u8 _SS:2;		// 0:1SS, 1:2SS, 2:3SS  
	s8 Power;		// dBm; MSB is sign bit
	u8 Active_Tx;		// number of antenna
} rate_power_t;

typedef struct rate_power_table_s {
	u8 channel;
	u8 rsvd;
	u16 NumOfEntry;		//number of valid entry in array RatePower
	u32 RatePower[MAX_RATE_POWER_ENTRY];
} rate_power_table_t;

typedef struct Info_rate_power_table_s {
	u32 DrvCnt;
	u32 FwCnt;
	rate_power_table_t RatePwrTbl;
} Info_rate_power_table_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_SET_POWER_PER_RATE {
	FWCmdHdr CmdHdr;
	u32 pPhyInfoPwrTbl;
} PACK_END HostCmd_FW_NEWDP_SET_POWER_PER_RATE,
	*PHostCmd_FW_NEWDP_SET_POWER_PER_RATE;

#endif

typedef PACK_START struct tagHostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION {
	FWCmdHdr CmdHdr;
	u32 Action;
} PACK_END HostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION,
	*PHostCmd_FW_NEWDP_RADIO_STATUS_NOTIFICATION;

typedef struct mu_stn_s {
	//  u8          RA[6];       
	u8 ActiveCnt;
	u16 StnId;
	u16 RateCode;		//not use??
	u32 Rateinfo;
#ifndef __KERNEL__
	SMAC_TXQ_ENTRY_st *txq;
#else
	u32 txq;
#endif

} mu_stn_t;

#if defined(SOC_W906X) || defined(SOC_W9068)
#define MU_MAX_USERS 16
#define MU_MIMO_MAX_USER 8
#define MU_OFDMA_MAX_USER 16
#else
#define MU_MAX_USERS 3
#endif

/* driver does not have LIST_ELEM_st struct, define it to pass driver compilation
   If fw changes the struct, driver should change the defeintion accordingly.
*/
#ifdef __KERNEL__
typedef struct LIST_ELEM_st {
	u32 next;
	u32 prev;
} LIST_ELEM_st;
#endif

typedef struct mu_sets_s {
#if defined(SOC_W906X) || defined(SOC_W9068)
	LIST_ELEM_st muLink;
#endif
	u8 GID;
	u8 Own;			// State of MU Set ownership (mu_own_*)
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 Schedule;
	u8 MaxUser;
	u32 txsounding_tickcnt;
	u32 timer_expiry;
#endif
	u32 type;		//11ac:0, 11ax:1
	mu_stn_t mustn[MU_MIMO_MAX_USER];
	u16 current_queue_stnid[MU_MIMO_MAX_USER];
	u32 sounduser;
} mu_sets_t;

typedef struct ofdma_sets_s {
	LIST_ELEM_st muLink;
	u8 Option;
	u8 Schedule;
	u8 MaxUser;
	u8 ru_mode;
	u32 index;
	u32 max_delay;
	u32 timer_expiry;
	mu_stn_t mustn[MU_MAX_USERS];
} ofdma_sets_t;

typedef PACK_START struct tagHostCmd_FW_GET_MU_SET {
	FWCmdHdr CmdHdr;
	mu_sets_t muset[1];
	u8 index;
} PACK_END HostCmd_FW_GET_MU_SET, *PHostCmd_GET_MU_SET;

typedef PACK_START struct tagHostCmd_FW_SET_MU_SET {
	FWCmdHdr CmdHdr;
	u8 Option;	     /** 1 : set 0 : delete **/
	u8 GID;
	u8 Setindex;
#if defined(SOC_W906X) || defined(SOC_W9068)
	u8 Ofdma;
#endif
	u16 StnID[MU_MIMO_MAX_USER];
} PACK_END HostCmd_FW_SET_MU_SET, *PHostCmd_SET_MU_SET;

//number of mbssid set support
#define MAX_MBSSID_SET 		4
typedef PACK_START struct tagHostCmd_FW_SET_MBSSID_SET {
	FWCmdHdr CmdHdr;
	u8 Option;	      /** 1 : set 0 : delete **/
	u8 sid;			//mbssid set id
	u8 Primary;		//Primary mbss id 
	u32 bitmap;		//mbsset members bitmap    
	u8 max_bss_indicator;	//max bssid Indicator
} PACK_END HostCmd_FW_SET_MBSSID_SET, *PHostCmd_SET_MBSSID_SET;

#if defined(SOC_W906X) || defined(SOC_W9068)
typedef PACK_START struct tagHostCmd_FW_OBW16_11B {
	FWCmdHdr CmdHdr;
	u8 Enable;
} PACK_END HostCmd_FW_OBW16_11B, *PHostCmd_OBW16_11B;
#endif

#ifdef MRVL_MUG_ENABLE
typedef PACK_START struct tagHostCmd_FW_GET_MU_INFO {
	FWCmdHdr CmdHdr;
	u8 groups_only;
} PACK_END HostCmd_FW_GET_MU_INFOT, *PHostCmd_GET_MU_INFO;

typedef PACK_START struct tagHostCmd_FW_SET_MU_CONFIG {
	FWCmdHdr CmdHdr;
	u32 corr_thr_decimal;
	u16 sta_cep_age_thr;
	u16 period_ms;
} PACK_END HostCmd_FW_SET_MU_CONFIGT, *PHostCmd_SET_MU_CONFIG;

typedef PACK_START struct tagHostCmd_FW_MUG_ENABLE {
	FWCmdHdr CmdHdr;
	u8 enable;
} PACK_END HostCmd_FW_MUG_ENABLET, *PHostCmd_MUG_ENABLE;

typedef PACK_START struct tagHostCmd_FW_SET_MU_DMA {
	FWCmdHdr CmdHdr;
	u32 dma_buf_base;
	u32 dma_buf_size;
} PACK_END HostCmd_FW_SET_MU_DMAT, *PHostCmd_SET_MU_DMA;
#endif /* #ifdef MRVL_MUG_ENABLE */

#define MAX_TLV_LEN           64
typedef PACK_START struct tagHostCmd_FW_TLV_CONFIG {
	FWCmdHdr CmdHdr;
	u16 TlvType;
	u16 TlvLen;
	u8 TlvData[MAX_TLV_LEN];
} PACK_END HostCmd_FW_TLV_CONFIG, *PHostCmd_TLV_CONFIG;

typedef PACK_START struct tagHostCmd_FW_TXCONTINUOUS {
	FWCmdHdr CmdHdr;
	u32 mode;
	u32 rate_info;
} PACK_END HostCmd_FW_TXCONTINUOUS, *PHostCmd_TXCONTINUOUS;
typedef struct amsducfg_s {
	u8 peeraddr[6];		//peer mac addr
	u8 amsduCfgEnable;	//0:disable, 1:enable
	u8 priority_aggr;
	u8 size;		//0: disable, 1:4k 2:8k, 3:11k        
} amsducfg_t;

typedef PACK_START struct tagHostCmd_FW_NEWDP_AMSDU_CFG {
	FWCmdHdr CmdHdr;
	amsducfg_t amsducfg;
} PACK_END HostCmd_FW_NEWDP_AMSDU_CFG, *PHostCmd_FW_NEWDP_AMSDU_CFG;

typedef PACK_START struct tagHostCmd_FW_NEWDP_RX_DETECT {
	FWCmdHdr CmdHdr;
	u8 rx_detect_params;
	u8 rx_detect_threshold1;
	u8 rx_detect_threshold2;
} PACK_END HostCmd_FW_NEWDP_RX_DETECT, *PHostCmd_FW_NEWDP_RX_DETECT;

typedef PACK_START struct tagHostCmd_FW_SET_SKU {
	FWCmdHdr CmdHdr;
	u32 sku;
} PACK_END HostCmd_FW_SET_SKU, *PHostCmd_FW_SET_SKU;

typedef PACK_START struct tagHostCmd_FW_DMATHREAD_START_CMD {
	FWCmdHdr CmdHdr;
} PACK_END HostCmd_FW_DMATHREAD_START_CMD, *PHostCmd_FW_DMATHREAD_START_CMD;

#define MAX_EEPROM_DATA 0x200
typedef PACK_START struct tagHostCmd_FW_EEPROM_CONFIG {
	FWCmdHdr CmdHdr;
	u16 action;		//HostCmd_ACT_GEN_READ,HostCmd_ACT_GEN_WRITE    
	u16 status;
	u32 offset;
	u32 len;
	u8 data[MAX_EEPROM_DATA];
} PACK_END HostCmd_FW_EEPROM_CONFIG, *PHostCmd_EEPROM_CONFIG;

typedef PACK_START struct tagHostCmd_FW_EEPROM_ACCESS {
	FWCmdHdr CmdHdr;
	u32 Action;
	u32 status;
} PACK_END HostCmd_FW_EEPROM_ACCESS, *PHostCmd_FW_EEPROM_ACCESS;

typedef PACK_START struct tagHostCmd_FW_NDPA_USETA {
	FWCmdHdr CmdHdr;
	u32 Enable;
} PACK_END HostCmd_FW_NDPA_USETA, *PHostCmd_FW_NDPA_USETA;

typedef PACK_START struct tagHostCmd_FW_GET_REGION_CODE {
	FWCmdHdr CmdHdr;
#if !defined(SOC_W906X) && !defined(SOC_W9068)
	u32 status;		// 0 = Found, 1 = Error
#endif
	u32 FW_Region_Code;
} PACK_END HostCmd_FW_GET_REGION_CODE, *PHostCmd_FW_GET_REGION_CODE;

//#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
// Settings from FW. Cross check against that during every update
#define HAL_TRPC_ID_MAX             32
#define MAX_GROUP_PER_CHANNEL_5G    39
#define MAX_GROUP_PER_CHANNEL_2G    21

#define _MAX(a,b) (((a)>(b))?(a):(b))
#define MAX_GROUP_PER_CHANNEL_RATE       _MAX(MAX_GROUP_PER_CHANNEL_5G, MAX_GROUP_PER_CHANNEL_2G)

typedef PACK_START struct {
	u8 channel;
	u8 grpPwr[MAX_GROUP_PER_CHANNEL_RATE];
	u8 txPwr[HAL_TRPC_ID_MAX];
	u8 DFS_Capable;
	u8 AxAnt;
	u8 CDD;
	u8 rsvd;
} PACK_END channel_power_tbl_t;

typedef PACK_START struct tagHostCmd_FW_GET_EEPROM_PWR_TBL {
	FWCmdHdr CmdHdr;
	u16 status;		// 0 = Found, 1 = Error
	u8 region_code;
	u8 number_of_channels;
	u32 current_channel_index;
	channel_power_tbl_t channelPwrTbl;	// Only for 1 channel, so, 1 channel at a time
} PACK_END HostCmd_FW_GET_EEPROM_PWR_TBL, *PHostCmd_FW_GET_EEPROM_PWR_TBL;
//#endif

typedef PACK_START struct _HostCmd_SET_RRM {
	FWCmdHdr CmdHdr;
	u32 rrm;		// 0 disable, 1 enable
} PACK_END HostCmd_SET_RRM, *PHostCmd_SET_RRM;

typedef PACK_START struct _HostCmd_SET_CH_UTIL {
	FWCmdHdr CmdHdr;
	u8 ch_util;		// 0 ~ 255
} PACK_END HostCmd_SET_CH_UTIL, *PHostCmd_SET_CH_UTIL;

typedef PACK_START struct _HostCmd_SET_QUIET {
	FWCmdHdr CmdHdr;
	u8 enable;
	u8 period;		// trigger quiet for every <period> beacon intervals
	u16 duration;		// quiet for <duration> ms
	u16 offset;		// trigger quiet at <offset> ms after target TBTT
	u16 offset1;		// netif_stop_queue before <offset1> ms of quiet
	u8 txStop_en;		// Enable/disable txStop for debugging purpose
} PACK_END HostCmd_SET_QUIET, *PHostCmd_SET_QUIET;

#ifdef WMM_AC_EDCA
typedef PACK_START struct _HostCmd_SET_BSS_LOAD_AAC {
	FWCmdHdr CmdHdr;
	u16 aac;		// Available Admission Capacity, in 32us unit
} PACK_END HostCmd_SET_BSS_LOAD_AAC, *PHostCmd_SET_BSS_LOAD_AAC;
#endif

/* Recent radio card CPU load with respect to load at "idle"
   in 4 times % units, e.g., 4 is 1% and 5 is 1.25% */
typedef struct radio_cpu_load_s {
	u32 load_onesec;
	u32 load_foursec;
	u32 load_eightsec;
	u32 load_sixteensec;
} radio_cpu_load_t;

typedef PACK_START struct tagHostCmd_FW_GET_SYSLOAD {
	FWCmdHdr CmdHdr;
	radio_cpu_load_t sysLoad;
} PACK_END HostCmd_FW_GET_SYSLOAD, *PHostCmd_GET_SYSLOAD;

#ifdef AIRTIME_FAIRNESS

typedef PACK_START struct tagHostCmd_FW_ATF_ENABLE {
	FWCmdHdr CmdHdr;
	u8 enable;
} PACK_END HostCmd_FW_ATF_ENABLE, *PHostCmd_ATF_ENABLE;

typedef PACK_START struct tagHostCmd_FW_SET_ATF_CFG {
	FWCmdHdr CmdHdr;
	u8 param;
	u16 value;
} PACK_END HostCmd_FW_SET_ATF_CFG, *PHostCmd_SET_ATF_CFG;

typedef PACK_START struct tagHostCmd_FW_GET_ATF_CFG {
	FWCmdHdr CmdHdr;
	u16 vi_weight;
	u16 be_weight;
	u16 bk_weight;
	u16 reserved_airtime;
} PACK_END HostCmd_FW_GET_ATF_CFG, *PHostCmd_GET_ATF_CFG;

typedef PACK_START struct tagHostCmd_FW_ATF_DEBUG_ENABLE {
	FWCmdHdr CmdHdr;
	u8 enable;
	u8 feature;
} PACK_END HostCmd_FW_ATF_DEBUG_ENABLE, *PHostCmd_ATF_DEBUG_ENABLE;

typedef PACK_START struct tagHostCmd_FW_SET_ATF_DMA {
	FWCmdHdr CmdHdr;
	u32 dma_buf_base;
	u32 dma_buf_size;
} PACK_END HostCmd_FW_SET_ATF_DMA, *PHostCmd_SET_ATF_DMA;

typedef PACK_START struct tagHostCmd_FW_ATF_TRANSFERT_DONE {
	FWCmdHdr CmdHdr;
} PACK_END HostCmd_FW_ATF_TRANSFERT_DONE, *PHostCmd_ATF_TRANSFERT_DONE;
#endif /* AIRTIME_FAIRNESS */

typedef PACK_START struct tagHostCmd_AP_CBMODE {
	FWCmdHdr CmdHdr;
	u8 mode;		//1: CB mode, 0: non-CB mode
	u32 bcnBasePtr;
} PACK_END HostCmd_AP_CBMODE, *PHostCmd_AP_CBMODE;

typedef PACK_START struct tagHostCmd_STA_CB_NOACK {
	FWCmdHdr CmdHdr;
	u16 staid;
	u8 mode;		//1: no ack active, 0: no ack deactive
} PACK_END HostCmd_STA_CB_NOACK, *PHostCmd_STA_CB_NOACK;

typedef PACK_START struct tagHostCmd_CB_PARAMS_SYNC {
	FWCmdHdr CmdHdr;
	u16 staid;
#ifndef DRV_SKIP_DEFINE
	STA_PW_t pwrState;	///< Power Save State of the Client (Peer)
#else
	U8 pwrState;		//enum in DRV is 4 bytes
#endif
	u16 sn[8];
	//security info need to be transferred.
	U8 euMode;		///< 0:CCMP, 1:WAPI, 2:CMAC, 3:BYPASS,
	///< 4:GCMP, 5:GMAC, 6:TKIP, 7:WEP
	U8 keyId[2];
	U8 pn[16];		///< PN for PTKSA: WAPI: 16 bytes, WEP: Not used, Others: 6 bytes
	U32 key[2][8];		///< [keyIdx]
	U8 keyRecIdx:4;		///< 0 or 1
	U8 pn_inc:4;		///< 1: Mcast or 2:Ucast for WAPI
	//Rx reordering is currently handled by driver
} PACK_END HostCmd_STA_CB_PARAMS_SYNC, *PHostCmd_STA_CB_PARAMS_SYNC;

#define FIPS_MAX_DATA_LEN     256
#define FIPS_MAX_NONCE_LEN     16
#define FIPS_MAX_AAD_LEN       32
#define FIPS_MAX_COUNTER    10000

typedef PACK_START struct {
	u16 Length;
	u8 Data[FIPS_MAX_DATA_LEN];
} PACK_END DataEntry_t;

typedef PACK_START struct tagHostCmd_FIPS_TEST {
	FWCmdHdr CmdHdr;
	u16 Status;
	u16 EncDec;
	u16 Algorithm;
} PACK_END HostCmd_FIPS_TEST, *PHostCmd_FIPS_TEST;

typedef PACK_START struct tagHostCmd_FW_SET_RESET_RATE_MODE {
	FWCmdHdr CmdHdr;
	u8 ResetRateMode;
} PACK_END HostCmd_FW_SET_RESET_RATE_MODE, *PHostCmd_FW_SET_RESET_RATE_MODE;

typedef PACK_START struct tagHostCmd_FW_GEN_U32_ACCESS {
	FWCmdHdr CmdHdr;
	u32 val;
	u8 set;
} PACK_END HostCmd_FW_FW_GEN_U32_ACCESS, *PHostCmd_FW_FW_GEN_U32_ACCESS;

typedef PACK_START struct tagHostCmd_SET_MCAST_CTS_TO_SELF {
	FWCmdHdr CmdHdr;
	u8 enable;
} PACK_END HostCmd_SET_MCAST_CTS_TO_SELF, *PHostCmd_SET_MCAST_CTS_TO_SELF;

typedef PACK_START struct tagHostCmd_MU_USER_POSITION {
	FWCmdHdr CmdHdr;
	u16 Action;
	u8 gid;
	u8 usr_pos;
} PACK_END HostCmd_MU_USER_POSIOTION, *PHostCmd_MU_USER_POSIOTION;

typedef struct {
	u32 address;
	u32 length;
} core_region_t;

typedef struct {
	char name[16];
	u32 address;
	u16 length;
	u16 entries;
} core_symbol_t;

#define MAX_CORE_REGIONS 32
#define MAX_CORE_SYMBOLS 30
typedef struct {
	u8 version_major;
	u8 version_minor;
	u8 version_patch;
	u8 hdr_version;
	u8 num_regions;
	u8 num_symbols;
	u8 fill[2];
	core_region_t region[MAX_CORE_REGIONS];
	core_symbol_t symbol[MAX_CORE_SYMBOLS];
	u32 fill_end[40];
} coredump_t;

typedef struct coredump_cmd_s {
	u32 context;
	u32 buffer;
	u32 buffer_len;
	u32 sizeB;
	u32 flags;
#define      MVL_COREDUMP_DIAG_MODE 0x00000001
#define      MVL_COREDUMP_INCL_EXT  0x00000002
} coredump_cmd_t;

typedef struct debug_mem_cmd_s {
	u32 set;
	u32 type;
#define      DEBUG_LOCAL_MEM        0
#define      DEBUG_BBP_REG          1
#define      DEBUG_PHY_REG          2
#define      DEBUG_EEPROM_MEM       3
#define      DEBUG_SAGE_MEM         4
	u32 addr;
	u32 val;
	u32 rsvd;
} debug_mem_cmd_t;

#define MAX_CORE_DUMP_BUFFER 2048

typedef PACK_START struct _HostCmd_FW_DIAG_MODE {
	FWCmdHdr CmdHdr;
	u16 Status;
} PACK_END HostCmd_FW_DIAG_MODE, *PHostCmd_FW_DIAG_MODE;

typedef PACK_START struct _HostCmd_FW_CORE_DUMP {
	FWCmdHdr CmdHdr;
	union {
		coredump_cmd_t coredump;
		debug_mem_cmd_t debug_mem;
	} cmd_data;
	/*Buffer where F/W Copies the Core Dump */
	char Buffer[MAX_CORE_DUMP_BUFFER];
} PACK_END HostCmd_FW_CORE_DUMP, *PHostCmd_FW_CORE_DUMP;
typedef PACK_START struct _HostCmd_FW_CORE_DUMP_ {
	FWCmdHdr CmdHdr;
	union {
		coredump_cmd_t coredump;
		debug_mem_cmd_t debug_mem;
	} cmd_data;
} PACK_END HostCmd_FW_CORE_DUMP_, *PHostCmd_FW_CORE_DUMP_;

typedef PACK_START struct _HostCmd_DEBUG_TXDROP_MODE {
	FWCmdHdr CmdHdr;
	u16 Enable;
	u16 Flag;		//0- by Qid, 1 - by StaId
	u32 id;
} PACK_END HostCmd_DEBUG_TXDROP_MODE, *PHostCmd_DEBUG_TXDROP_MODE;

#ifdef DSP_COMMAND
typedef PACK_START struct _HostCmd_DSP_CMD {
	FWCmdHdr CmdHdr;
	u8 cmdIndex;
	u8 cmdFlag;
	u8 cmdPriority;
	u8 cmdResult;
	u32 cmdSeqNum;
	u32 ptrSrcData;
	u32 srcDataLen;
	u32 ptrDstData;
	u32 dstDataLen;
} PACK_END HostCmd_DSP_CMD, *PHostCmd_DSP_CMD;
#endif

/* ----------------  Status -------------------*/
#define MAX_NF_DBM_LEN 20
typedef struct {
	u32 len;
	u32 error_code;
	u32 noise;		/* one second noise max */
	u32 noiseavg;		/* 60 sec noise avg */
	u32 noisemax;		/* 60 sec noise max */
	u32 load;		/* our generated load (rx + tx) */
	u32 rxload;		/* our generated rx load */
	u32 rxload_cc;		/* co-channel rx load */
	u32 temperature;
	u32 total_load;		/* total channel load */
	u32 rxsens;
	u32 td;
	u32 tdr;
	u32 tw;
	u32 tu_vc;
	u32 tu_vc_cc;		/* voice utilization on co-channel */
	u32 ap_load;		/* 1sec generated load */
	u32 too_many_power;
	u32 probe_table_size;
	u32 host_timestamp;
#define OFF_CHNL_PRIORITY_TYPE        5
	u16 avg_wait_time[OFF_CHNL_PRIORITY_TYPE];	//in ms
	u16 avg_serve_time[OFF_CHNL_PRIORITY_TYPE];	//in ms
	u32 pm_dwell;		/*ELM - promiscuous mode dwelling (%) */
	u32 channel;
	u32 nf_dbm[MAX_NF_DBM_LEN];
} mvl_status_t;

//for HostCmd_CMD_GET_MVL_RADIO_STATUS
typedef PACK_START struct tagHostCmd_FW_GET_MVL_RADIO_STATUS {
	FWCmdHdr CmdHdr;
	mvl_status_t radio_status;
} PACK_END HostCmd_FW_GET_MVL_RADIO_STATUS, *PHostCmd_FW_GET_MVL_RADIO_STATUS;

typedef PACK_START struct tf_common_s {
	u8 tf_type;
	u8 tf_ldpc_extra;
	u8 tf_more_flag:1;
	u8 tf_cs_required:1;
	u8 reserved:6;
	u8 tf_ap_tx_power;

	u16 tf_ul_len;
	u16 tf_ul_spatial_reuse;

	u8 tf_bw;
	u8 tf_gi_ltf;
	u8 tf_mumimo_ltf_mode;
	u8 tf_stbc;

	u8 tf_no_heltf_sym;
	u8 tf_max_pe;
	u8 tf_a_factor_init;
	u8 tf_num_users;

	u8 tf_doppler;
	u8 tf_mu_rts;
	u16 tf_nsym_init;

	u8 tf_midamble_period;
	u8 tf_en_mdrhpf;
	u16 tf_hesiga_rsvd;
} PACK_END tf_common_t;

typedef PACK_START struct tf_user_info_s {
	u16 staId;
	u16 csi;
	u8 reserved;
	u8 tf_mpdu_spac_fac;
	u8 tf_tid_aggr_limit;
	union {
		u8 tf_pref_ac;
		u8 tf_fb_bitmap;
	};
	u8 tf_ru_allocation;
	u8 tf_fec_type;
	u8 tf_mcs;
	u8 tf_start_ss;

	u8 tf_dcm;
	u8 tf_nss;
	u8 tf_target_rssi;
	u8 tf_ru_alloc_idx;
	u8 tf_rssi_delta;
	u32 tf_datalen;
} PACK_END tf_user_info_t;

typedef PACK_START struct tf_basic_s {
	tf_common_t common;
	tf_user_info_t user[SMAC_MAX_OFDMA_USERS];
} PACK_END tf_basic_t;

typedef PACK_START struct _HostCmd_DS_TRIGGER_FRAME {
	FWCmdHdr CmdHdr;
	u16 status;
	u8 action;		//0: disable 1: use sentId array, 2: hardcoded
	u8 type;		//1: UL-MUMIMO, 2: UL-OFDMA
	u32 period;		//unit: ms, 0: one time trigger
	u32 rateInfo;
	u16 padNum;
	u16 rsvd;
	union {
		tf_basic_t tf;
	};
} PACK_END HostCmd_DS_TRIGGER_FRAME, *PHostCmd_DS_TRIGGER_FRAME;

#define MAX_TX_FRAME_LEN   1200

typedef PACK_START struct _HostCmd_DS_TX_FRAME_TEST {
	FWCmdHdr CmdHdr;
	u16 status;
	u16 reserved;

	u16 reportId;		//0 <-- no need to report
	u16 staIdx;		//0xffff <-- bcast/mcast (0~319)

	u32 rateInfo;
	u8 tid;
	u8 machdrLen;
	u16 payloadLen;
	u8 data[1200];		// mac + payLoad
} PACK_END HostCmd_DS_TX_FRAME_TEST, *PHostCmd_DS_TX_FRAME_TEST;

typedef PACK_START struct tagHostCmd_FW_SET_BEAM_CHANGE {
	FWCmdHdr CmdHdr;
	u8 enable;
} PACK_END HostCmd_FW_SET_BEAM_CHANGE, *PHostCmd_SET_BEAM_CHANGE;

#if defined(SOC_W906X) || defined(SOC_W9068)
typedef PACK_START struct tagHostCmd_FW_BCN_GPIO17_TOGGLE {
	FWCmdHdr CmdHdr;
	u8 action;		// Set = 1; Get = 0
	u8 enable;
} PACK_END HostCmd_FW_BCN_GPIO17_TOGGLE, *PHostCmd_FW_BCN_GPIO17_TOGGLE;
#endif

//WFA section
#define MODE_SELECT_SU            BIT(0)
#define MODE_SELECT_MUMIMO        BIT(1)
#define MODE_SELECT_DL_OFDMA      BIT(2)
#define MODE_SELECT_UL_OFDMA      BIT(3)
#define MODE_SELECT_WFA           BIT(8)
#define MODE_SELECT_CNTI          BIT(9)
#define MODE_SELECT_BSRP_OFF      BIT(10)
#define MODE_SELECT_AUTO_PC_OFF   BIT(11)
#define MODE_SELECT_AUTO_DRA_OFF  BIT(12)

typedef PACK_START struct ul_ofdma_s {
	u32 maxStaNum;
	u32 maxDelayTime;
} PACK_END ul_ofdma_t;

typedef PACK_START struct _HostCmd_WFA_TEST_CMD {
	FWCmdHdr CmdHdr;
	u16 status;
	u16 action;
	u32 version;
	u32 testId;
	u32 stepId;
	//ul_ofdma_t        ul;
} PACK_END HostCmd_WFA_TEST_CMD, *PHostCmd_WFA_TEST_CMD;

typedef enum {
	MIB_TF_DRA_MODE,
	MIB_TF_MAX_PE,
	MIB_TF_ALPHA,
	MIB_TF_ETA,
	MIB_TF_MAX_AP_RSSI,
	MIB_TF_CS_REQUIRED,
	MIB_TF_GI_LTF,
	MIB_TF_MCS,
	MIB_TF_NSS,
	MIB_TF_FB_BITMAP,
	MIB_TF_TGT_RSSI,
	MIB_TF_TGT_PER,		//0.2 or 0.3, so input as 2 or 3
	MIB_TF_A_STEP,		//unit 1 dB
	MIB_TF_FEC_TYPE,
	MIB_TF_DCM,
	MIB_TF_RU_ALLOC,
	MIB_TF_DATA_LEN,
	MIB_TF_EXTRA_SPACE,
	MIB_TF_BSRP_LEN,
	MIB_TF_SS_START,
	MIB_TF_BW,
	MIB_TXINFO_TF_TYPE,	//1:MU-MIMO, 2:OFDMA(default)
	MIB_TF_TYPE,
	MIB_TF_DELTA,
	MIB_EBF_INSUF_NDP_ENABLE,
	MIB_TF_MU_RTS,
	MIB_OFDMA_MUMIMO_AUTO,
	MIB_OFDMA_MUMIMO_LEN,
	MIB_TF_MU_ACK_SEQ,
	MIB_TF_MU_ACK_ACTION_MODE,
	MIB_TF_MU_ACK_MCS,
	MIB_TF_MU_ACK_NSS,
	MIB_TF_MU_ACK_LEN,
	MIB_TF_MU_ACK_TGT_RSSI,
	MIB_TF_OFDMA_TXOP,
	MIB_TF_NOSIG_COUNT_THRES,
	MIB_MAX,
} MIB_DEF;

typedef PACK_START struct _HostCmd_FW_MIB_CFG {
	FWCmdHdr CmdHdr;
	u16 action;
	u16 rsrvd;
	u16 mibIdx;
	u16 num;
	U32 value[SMAC_MAX_OFDMA_USERS];
} PACK_END HostCmd_FW_MIB_CFG, *PHostCmd_FW_MIB_CFG;

typedef PACK_START struct sched_cfg_ul_ofdma_s {
	u32 minUserInfo;
	u32 period_tmr;
	u32 gap_tmr;		//between BSRP and Basic TF      
	u32 rateInfo;
	u32 maxUserInfo;
} PACK_END sched_cfg_ul_ofdma_t;

typedef PACK_START struct sched_cfg_test_s {
	u8 tf_type;
	u8 rsvd[3];
	u32 rateInfo;

	u32 param[2];
} PACK_END sched_cfg_test_t;

typedef PACK_START struct _HostCmd_SCHED_MODE_CFG {
	FWCmdHdr CmdHdr;
	u16 action;
	u16 status;
	u32 mode_selected;
	union {
		sched_cfg_ul_ofdma_t ul_ofdma;
		sched_cfg_test_t test;
		u32 partial_mode;
	};
} PACK_END HostCmd_SCHED_MODE_CFG, *PHostCmd_SCHED_MODE_CFG;

typedef PACK_START struct tagHostCmd_FW_SET_SR {
	FWCmdHdr CmdHdr;

	u8 srEnable;		//1: spatial reuse enabled, 0: disabled
	s8 thresNonSrg;		//Spatial reuse threshold in 2's complement. s8 data type range can't exceed -128
	s8 thresSrg;
	u8 rsvd;
} PACK_END HostCmd_FW_SET_SR, *PHostCmd_FW_SET_SR;

typedef PACK_START struct tagHostCmd_FW_GET_STA_STATS {
	FWCmdHdr CmdHdr;
	unsigned int StaId;
	SMAC_STA_STATISTICS_st StaStats;
} PACK_END HostCmd_FW_GET_STA_STATS, *PHostCmd_FW_GET_STA_STATS;

typedef PACK_START struct tagHostCmd_FW_SET_OFDMA_SET {
	FWCmdHdr CmdHdr;
	u8 Option;	     /** 1 : OFDMA TRUE, 0 : OFDMA FALSE **/
	u8 sta_count;
	u16 StnID[MU_OFDMA_MAX_USER];
} PACK_END HostCmd_FW_SET_OFDMA_SET, *PHostCmd_FW_SET_OFDMA_SET;

typedef PACK_START struct ul_stnid_ru_s {
	u16 StnID;
	u16 RU_alloc;		/* [0]: ru_allocation region
				 *      1: 2 STA(996 + 996)
				 *      0: others
				 * [1:7]: ru_allocation 0 ~67
				 *
				 * [8:9] fec_type
				 *      0: reserved
				 *      1: bcc
				 *      2:ldpc
				 * [10:15]: reserved, set to 0 */

	u8 SU_Rate_NSS;		/* 0:1SS ...7:8SS, Others: reserved */
	u8 SU_Rate_MCS;		/* 0~11, Others: reserved */
	s16 SU_rssi;		/* Signed Value */
	u32 CSI;		/* TBD */
	u32 DataLen;		/* Unit: Byte */
} PACK_END ul_stnid_ru_t;

typedef PACK_START struct tagHostCmd_FW_SET_ULMU_SET {
	FWCmdHdr CmdHdr;
	u16 Action;		/* HostCmd_ACT_GEN_SET, HostCmd_ACT_GEN_DEL */
	u16 Version;		/* If the structure changes, must change the version */
	u32 RateInfo;		/* The Tx Rate for trigger frame */
	u32 Flag;		/* [0]: Reinitialize SU Rate, 1: StaList changed, Oterhs: reserved */
	u16 GID;
	u8 Mode;		/* TXINFO_TF_TYPE_MUMIMO, TXINFO_TF_TYPE_OFDMA */
	u8 BandWidth;		/* BW_20MHz = 0 ... BW_160MHz = 3 */
	u8 Reserved[5];
	u8 StaNum;
	ul_stnid_ru_t StaList[MU_MAX_USERS];
} PACK_END HostCmd_FW_SET_ULMU_SET, *PHostCmd_FW_SET_ULMU_SET;

typedef PACK_START struct tagHostCmd_FW_SET_ANCT_WITH_MU {
	FWCmdHdr CmdHdr;
	u16 Action;		/* HostCmd_ACT_GEN_SET: enable acnt record with DL mu. HostCmd_ACT_GEN_DEL:disable it */
} PACK_END HostCmd_FW_SET_ANCT_WITH_MU, *PHostCmd_FW_SET_ANCT_WITH_MU;

typedef PACK_START struct tagHostCmd_FW_SET_STA_AWAKE {
	FWCmdHdr CmdHdr;
	u16 Action;
	u16 stnid;
	u16 forceAwake;
} PACK_END HostCmd_FW_SET_STA_AWAKE, *PHostCmd_FW_SET_STA_AWAKE;

#endif /* __HOSTCMD__H */
