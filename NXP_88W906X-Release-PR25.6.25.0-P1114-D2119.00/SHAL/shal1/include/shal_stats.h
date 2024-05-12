/** @file shal_stats.h
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
 * @brief SMAC statistics records.
 */

#ifndef _SHAL_STATS_H_
#define _SHAL_STATS_H_

//per STA stats
typedef struct SMAC_STA_STATISTICS_st {
	U32 dot11MPDUCount;
	U32 dot11SuccessCount;
	U32 dot11RetryCount;
	U32 dot11FrameDuplicateCount;	//
	U32 dot11ReceivedFragmentCount;	//
	U32 dot11FCSErrorCount;	//
	U32 dot11WEPUndecryptableCount;	///< Done

	//U32 dot11RSNAStatsCCMPReplays;
	//U32 dot11RSNAStatsCCMPDecryptErrors;
	//U32 dot11RSNAStatsTKIPReplays;
	U32 dot11FailedRertransCount;	/*failed transmitted  due to the number of retransmission attempts exceeding retry limit */
	U32 dot11RetryCount_1;	/*successfully transmitted after one or more retransmissions */
	U32 dot11MultipleRetryCount;	/*successfully transmitted after more than one retransmission */
	U32 dot11RSNAStatsCMACICVErrors;
	U32 dot11RSNAStatsCMACReplays;
	U32 dot11RSNAStatsRobustMgmtCCMPReplays;
	U32 dot11WAPIStatsWPIReplayCounters;
	U32 dot11WAPIStatsWPIMICErrors;
} SMAC_STA_STATISTICS_st;

/// Dot11CountersEntry - Same as dot11CountersGroup3 except the last 2 counters
//NOTE / TODO: do not add to the below structures
//If any member needs to be used, move it to SMAC_STA_STATISTICS_st
//The following two structures will be eventually deleted
//typedef struct STATS_D11_COUNTERS_st
//{
//    U32 dot11TransmittedFragmentCount;
//    U32 dot11GroupTransmittedFrameCount;
//    U32 dot11FailedCount;
//    U32 dot11MultipleRetryCount;
//    U32 dot11RTSSuccessCount;         ///< CTS is received in response to an RTS
//    U32 dot11RTSFailureCount;         ///< CTS is NOT received in response to an RTS
//    U32 dot11ACKFailureCount;         ///< ACK is not received when expected
//    U32 dot11GroupReceivedFrameCount; //
//    U32 dot11TransmittedFrameCount;
//    U32 dot11QosDiscardedFragmentCount; ///< each QoS Data MPDU that has been discarded
//    U32 dot11AssociatedStationCount;    ///< only available in AP
//    U32 dot11QosCFPollsReceivedCount;   ///< each QoS (+)CF-Poll that has been received
//    U32 dot11QosCFPollsUnusedCount;     ///< received but not used.
//    U32 dot11QosCFPollsUnusableCount; /**< could not be used due to the TXOP size being
					 //    smaller than the time that is required for one frame exchange sequence
					 //*/
#if 0
U32 dot11QosCFPollsLostCount;	///< No response to the issued QoS(+)CF-Poll
U32 dot11TransmittedAMSDUCount;
U32 dot11FailedAMSDUCount;
U32 dot11RetryAMSDUCount;
U32 dot11MultipleRetryAMSDUCount;
U32 dot11TransmittedOctetsInAMSDUCount_64;
U32 dot11AMSDUAckFailureCount;
U32 dot11ReceivedAMSDUCount;	//
U32 dot11ReceivedOctetsInAMSDUCount_64;	//
U32 dot11TransmittedAMPDUCount;
U32 dot11TransmittedMPDUsInAMPDUCount;
U32 dot11TransmittedOctetsInAMPDUCount_64;
U32 dot11AMPDUReceivedCount;	//
U32 dot11MPDUInReceivedAMPDUCount;	//
U32 dot11ReceivedOctetsInAMPDUCount_64;	///< before or after decryption?
U32 dot11AMPDUDelimiterCRCErrorCount;	///< HW support
U32 dot11ImplicitBARFailureCount;
U32 dot11ExplicitBARFailureCount;
dot11ChannelWidthSwitchCount;
dot11TwentyMHzFrameTransmittedCount;
dot11FortyMHzFrameTransmittedCount;
dot11TwentyMHzFrameReceivedCount;
dot11FortyMHzFrameReceivedCount;
dot11PSMPUTTGrantDuration;	///< in units of 4 microseconds
dot11PSMPUTTUsedDuration;	///< in units of 4 microseconds
dot11GrantedRDGUsedCount;
dot11GrantedRDGUnusedCount;
dot11TransmittedFramesInGrantedRDGCount;
dot11TransmittedOctetsInGrantedRDGCount_64;
dot11BeamformingFrameCount;	///< Tx
dot11DualCTSSuccessCount;	///< AP Tx ^
dot11DualCTSFailureCount;
dot11STBCCTSSuccessCount;
dot11STBCCTSFailureCount;
dot11nonSTBCCTSSuccessCount;
dot11nonSTBCCTSFailureCount;	///< AP Tx ^
dot11RTSLSIGSuccessCount;	///< RTS <- CTS(DUR) in EPP mode
dot11RTSLSIGFailureCount;
dot11PBACErrors;		///< BAR  WinEndB < SSN < WinStartB
dot11DeniedAssociationCounterDueToBSSLoad;
#endif
//} STATS_D11_COUNTERS_st;

/// Dot11RSNAStatsEntry
//typedef struct STATS_D11_RSNA_st
//{
//    U32 dot11RSNAStatsTKIPICVErrors;
//    U32 dot11RSNAStatsTKIPLocalMICFailures;
//    U32 dot11RSNAStatsTKIPRemoteMICFailures;
//    U32 dot11RSNABIPMICErrors;
// WAPI
//    U32 dot11WAPIStatsWPIDecryptableErrors;
//} STATS_D11_RSNA_st;

#endif				// _SHAL_STATS_H_
