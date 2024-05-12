/** @file ap8xLnxCsi.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
  *
  * NXP CONFIDENTIAL
  * The source code contained or described herein and all documents related to
  * the source code ("Materials") are owned by NXP, its
  * suppliers and/or its licensors. Title to the Materials remains with NXP,
  * its suppliers and/or its licensors. The Materials contain
  * trade secrets and proprietary and confidential information of NXP, its
  * suppliers and/or its licensors. The Materials are protected by worldwide copyright
  * and trade secret laws and treaty provisions. No part of the Materials may be
  * used, copied, reproduced, modified, published, uploaded, posted,
  * transmitted, distributed, or disclosed in any way without NXP's prior
  * express written permission.
  *
  * No license under any patent, copyright, trade secret or other intellectual
  * property right is granted to or conferred upon you by disclosure or delivery
  * of the Materials, either expressly, by implication, inducement, estoppel or
  * otherwise. Any license under such intellectual property rights must be
  * express and approved by NXP in writing.
  *
  */
#ifndef AP8X_CSI_H_
#define AP8X_CSI_H_

#ifndef DEF_TYPES
#define DEF_TYPES
#define SINT8	signed char
#define SINT16	signed short
#define SINT32	signed int
#define SINT64	signed long long
#define UINT8	unsigned char
#define UINT16	unsigned short
#define UINT32	unsigned int
#define UINT64	unsigned long long
#endif

// CSI Processing
#define HEADER_LEN 0x15
#define MAX_FFT_SIZE 1024
#define TWIDDLE_BIPT 15

//#define WLS_CSI_DUMP

#ifdef WLS_TDDE_EN
#define WLS_DEBUG_BUFFER_NUM 20
#define WLS_DEBUG_BUFFER_LEN 13
#else
#define WLS_DEBUG_BUFFER_NUM 32
#define WLS_DEBUG_BUFFER_LEN 9
#endif
#ifdef WLS_CSI_DUMP
#define CSI_BUFF_DW 512*2	// for SC5
#endif

// DW0: 0xABCD | dialogToken | z1/rx_timestamp (39:32)
// DW1: z1/rx_timestamp (0:31)
// DW2: z4/dta (11 bit) | z6/ cfo (20 bit)
// DW3: Z5/tx_timestamp
// DW4: firstPath | phaseRoll
// DW5: hal_pktinfo (0:31)

#define IFFT_OSF_SHIFT 2
#define FFT_ADV_FRAC 16
#define TD_FRAC_OF_FFT 4
#define PEAK_THRESH_SHIFT 2	// consider peaks up to 6 dB below peak
#define PEAK_THRESH_MIN_ABS 0xC00	// 3/64=0.0469 0x1400 // 5/64=0.0781 in p16
#define SUBBAND_DET_THRESH 4	// 18 dB
#define REMOVE_IIR 2
//#define USE_AOA_CAL_DATA

#define TOA_FPATH_BIPT 12

//#define ARM_DS5
//#define HAL_LOG(...) do { } while(0)

//#define DEBUG_OUT_FD
//#define DEBUG_OUT_TD
//#define DEBUG_CYCLE_TIME

#define MAX_CSI_PROCESSING_ARRAY_SIZE (8 + (9))	//Up to (3 peaks * 3) + 8; Do not go below 17, allow full mem size for debug.

#define MAX_IFFT_SIZE_SHIFT 4
#define MIN_IFFT_SIZE_SHIFT 1
#define MAX_IFFT_SIZE_CSI (64<<MAX_IFFT_SIZE_SHIFT)
#define MIN_IFFT_SIZE_CSI (64<<MIN_IFFT_SIZE_SHIFT)

#define IIR_FORMAT_NP 12
#define IIR_FORMAT_NB 16

#define MAX_RX 8
#define MAX_TX 1

#define CSI_SCRATCH_BFR_DW ((MAX_RX*MAX_TX+1)*MAX_IFFT_SIZE_CSI)

#define ONE_OVER_PIE_16P15 0x28BE

#define MPY_BIPT 12
#define ONE_OVER_PI ((0x145F306D)>>(30-MPY_BIPT))	//0x145F306D=1.0/PI*(1<<30)

#define VAC_LIGHTSPEED_MM_MICROSEC 300000
#define CABLE_LIGHTSPEED_MM_MICROSEC 200000

//#define MAX_NUM_SUBBANDS 8 // 20 MHz subbands in 160 MHz
#define NUM_ATAN_IT 10

typedef struct hal_pktinfo {
	UINT32 packetType:3;
	UINT32 psb:3;
	UINT32 sigBw:2;
	UINT32 Ng:1;
	UINT32 nTx:3;
	UINT32 nRx:3;
	UINT32 rxDevBw:2;
	UINT32 MU:1;
	UINT32 HELTF:2;
	UINT32 NgDsfShift:2;	// added to pass parameters
	UINT32 fftSize:4;
	UINT32 rsvd1:4;
	UINT32 scOffset:12;
	UINT32 rsvd2:20;
} hal_pktinfo_t;

typedef struct hal_wls_aoa_processing_input_params {
	UINT32 enableCsi:1;	// turn on CSI processing
	UINT32 enableAoA:1;	// turn on AoA (req. enableCsi==1)
	UINT32 nTx:3;		// limit # tx streams to process
	UINT32 nRx:3;		// limit # rx to process
	UINT32 selCal:8;	// choose cal values
	UINT32 dumpMul:2;	// dump extra peaks in AoA
	UINT32 enableAntCycling:1;	// enable antenna cycling
	UINT32 dumpRawAngle:1;	// Dump Raw Angle
	UINT32 useTaoMin:2;	// 0: power combining; 1: use min, 2/3 open;
	UINT32 useFindAngleDelayPeaks:1;	// use this algorithm for AoA
	UINT32 numCsiBufferSearch:3;	// number of additional CSI bufferes to search
	UINT32 variableCsiDelay:3;	// times 20 micro sec, range from 0-140 micro sec counter
	UINT32 rsvd1:3;
} hal_wls_aoa_processing_input_params_t;

typedef struct hal_wls_packet_params {
	UINT32 chNum:8;		// ch_index 1-4, 36:4:140, 149:4:165
	//UINT32 isFtmInit:1; // -- no longer used -- indicate if this is FTM exchange initiator or responder
	UINT32 ftmSignalBW:3;	// Channel bandwidth 0: 20 MHz, 1: 40 MHz, 2: 80 MHz, 3: 160 Mhz, 4-7 reserved
	//UINT32 ftmPacketType:2; // -- no longer used -- Format of FTM exchange 0: legacy, 1:HT, 3:VHT
	UINT32 freqBand:1;	// Declare freq. band, 0: 2.4 GHz, 1: 5 GHz
	UINT32 rsvd1:20;
	//UINT32 peerMacAddress_lo:16; // -- no longer used --  first 16 bit of FTM peer MAC address
	//UINT32 peerMacAddress_hi; // -- no longer used -- rest of FTM peer MAC address
	//UINT32 info_tsf; // -- no longer used -- TSF counter from tx/rx-info
	UINT32 cal_data_low_A:10;
	UINT32 cal_data_low_B:10;
	UINT32 cal_data_low_C:10;
	UINT32 rsvd2:2;
	UINT32 cal_data_low_D:10;
	UINT32 cal_data_low_E:10;
	UINT32 cal_data_low_F:10;
	UINT32 rsvd3:2;
	UINT32 cal_data_high_A:10;
	UINT32 cal_data_high_B:10;
	UINT32 cal_data_high_C:10;
	UINT32 rsvd4:2;
	UINT32 cal_data_high_D:10;
	UINT32 cal_data_high_E:10;
	UINT32 cal_data_high_F:10;
	UINT32 rsvd5:2;
	UINT32 cal_data_low_G:10;
	UINT32 cal_data_high_G:10;
	UINT32 rsvd6:12;
	UINT32 cable_len_A:8;
	UINT32 cable_len_B:8;
	UINT32 cable_len_C:8;
	UINT32 cable_len_D:8;
	UINT32 cable_len_E:8;
	UINT32 cable_len_F:8;
	UINT32 cable_len_G:8;
	UINT32 antenna_spacing:8;
} hal_wls_packet_params_t;

typedef struct hal_cal_struc {
	short calData[4];
	short centerFreq;
} hal_cal_struc_t;

#define SPATIAL_RES 64		// number of angular bins
#define NUM_MAX_PEAKS 32	// max number of angle/delay peaks to keep
#define DELAY_DELTA_SHIFT 4
#define STEP_SIZE (MAX_IFFT_SIZE_CSI/SPATIAL_RES)

#define RX_A 0
#define RX_B 1
#define RX_C 2
#define RX_D 3
#define REF_ANTENNA RX_D

#define CAL_FORMAT_NP 10
#define CAL_FORMAT_NB 16

#define NUM_CAL_CH_5G 10
#define NUM_CAL_CH_2G 2

#ifdef REMOVE_IIR
#define P(x) (((x*REMOVE_IIR*MAX_FFT_SIZE)>>IIR_FORMAT_NP)&(MAX_FFT_SIZE-1))	// adjust index format to twiddle table
//static SINT16 phiCorr512[512] ={P(-2560), P(-2488), P(-2417), P(-2348), P(-2281), P(-2218), P(-2158), P(-2101), P(-2049), P(-1999), P(-1953), P(-1910), P(-1870), P(-1832), P(-1796), P(-1763), P(-1731), P(-1701), P(-1673), P(-1646), P(-1620), P(-1595), P(-1572), P(-1549), P(-1527), P(-1506), P(-1486), P(-1466), P(-1447), P(-1429), P(-1411), P(-1393), P(-1376), P(-1360), P(-1344), P(-1328), P(-1313), P(-1297), P(-1283), P(-1268), P(-1254), P(-1241), P(-1227), P(-1214), P(-1201), P(-1188), P(-1176), P(-1163), P(-1151), P(-1139), P(-1128), P(-1116), P(-1105), P(-1094), P(-1083), P(-1072), P(-1061), P(-1051), P(-1040), P(-1030), P(-1020), P(-1010), P(-1001), P(-991), P(-981), P(-972), P(-963), P(-954), P(-945), P(-936), P(-927), P(-918), P(-910), P(-901), P(-893), P(-885), P(-877), P(-869), P(-861), P(-853), P(-845), P(-837), P(-829), P(-822), P(-814), P(-807), P(-800), P(-792), P(-785), P(-778), P(-771), P(-764), P(-757), P(-750), P(-744), P(-737), P(-730), P(-724), P(-717), P(-711), P(-704), P(-698), P(-691), P(-685), P(-679), P(-673), P(-667), P(-661), P(-655), P(-649), P(-643), P(-637), P(-631), P(-625), P(-619), P(-614), P(-608), P(-602), P(-597), P(-591), P(-586), P(-580), P(-575), P(-569), P(-564), P(-558), P(-553), P(-548), P(-543), P(-537), P(-532), P(-527), P(-522), P(-517), P(-512), P(-507), P(-502), P(-497), P(-492), P(-487), P(-482), P(-477), P(-472), P(-467), P(-462), P(-457), P(-453), P(-448), P(-443), P(-438), P(-434), P(-429), P(-424), P(-420), P(-415), P(-410), P(-406), P(-401), P(-397), P(-392), P(-388), P(-383), P(-379), P(-374), P(-370), P(-365), P(-361), P(-357), P(-352), P(-348), P(-343), P(-339), P(-335), P(-330), P(-326), P(-322), P(-318), P(-313), P(-309), P(-305), P(-301), P(-296), P(-292), P(-288), P(-284), P(-280), P(-276), P(-271), P(-267), P(-263), P(-259), P(-255), P(-251), P(-247), P(-243), P(-238), P(-234), P(-230), P(-226), P(-222), P(-218), P(-214), P(-210), P(-206), P(-202), P(-198), P(-194), P(-190), P(-186), P(-182), P(-178), P(-174), P(-170), P(-166), P(-162), P(-159), P(-155), P(-151), P(-147), P(-143), P(-139), P(-135), P(-131), P(-127), P(-123), P(-119), P(-116), P(-112), P(-108), P(-104), P(-100), P(-96), P(-92), P(-88), P(-85), P(-81), P(-77), P(-73), P(-69), P(-65), P(-61), P(-58), P(-54), P(-50), P(-46), P(-42), P(-38), P(-35), P(-31), P(-27), P(-23), P(-19), P(-15), P(-11), P(-8), P(-4), P(0), P(4), P(8), P(11), P(15), P(19), P(23), P(27), P(31), P(35), P(38), P(42), P(46), P(50), P(54), P(58), P(61), P(65), P(69), P(73), P(77), P(81), P(85), P(88), P(92), P(96), P(100), P(104), P(108), P(112), P(116), P(119), P(123), P(127), P(131), P(135), P(139), P(143), P(147), P(151), P(155), P(159), P(162), P(166), P(170), P(174), P(178), P(182), P(186), P(190), P(194), P(198), P(202), P(206), P(210), P(214), P(218), P(222), P(226), P(230), P(234), P(238), P(243), P(247), P(251), P(255), P(259), P(263), P(267), P(271), P(276), P(280), P(284), P(288), P(292), P(296), P(301), P(305), P(309), P(313), P(318), P(322), P(326), P(330), P(335), P(339), P(343), P(348), P(352), P(357), P(361), P(365), P(370), P(374), P(379), P(383), P(388), P(392), P(397), P(401), P(406), P(410), P(415), P(420), P(424), P(429), P(434), P(438), P(443), P(448), P(453), P(457), P(462), P(467), P(472), P(477), P(482), P(487), P(492), P(497), P(502), P(507), P(512), P(517), P(522), P(527), P(532), P(537), P(543), P(548), P(553), P(558), P(564), P(569), P(575), P(580), P(586), P(591), P(597), P(602), P(608), P(614), P(619), P(625), P(631), P(637), P(643), P(649), P(655), P(661), P(667), P(673), P(679), P(685), P(691), P(698), P(704), P(711), P(717), P(724), P(730), P(737), P(744), P(750), P(757), P(764), P(771), P(778), P(785), P(792), P(800), P(807), P(814), P(822), P(829), P(837), P(845), P(853), P(861), P(869), P(877), P(885), P(893), P(901), P(910), P(918), P(927), P(936), P(945), P(954), P(963), P(972), P(981), P(991), P(1001), P(1010), P(1020), P(1030), P(1040), P(1051), P(1061), P(1072), P(1083), P(1094), P(1105), P(1116), P(1128), P(1139), P(1151), P(1163), P(1176), P(1188), P(1201), P(1214), P(1227), P(1241), P(1254), P(1268), P(1283), P(1297), P(1313), P(1328), P(1344), P(1360), P(1376), P(1393), P(1411), P(1429), P(1447), P(1466), P(1486), P(1506), P(1527), P(1549), P(1572), P(1595), P(1620), P(1646), P(1673), P(1701), P(1731), P(1763), P(1796), P(1832), P(1870), P(1910), P(1953), P(1999), P(2049), P(2101), P(2158), P(2218), P(2281), P(2348), P(2417), P(2488)};
#endif

// RTT Processing
#define BIT_SHIFTL(B, N)      ( (unsigned long long)(B) << (N) )
//#define BIT_SHIFTR(B, N)      ( (unsigned long long)(B) >> (N) )
#define CONVERT_TO_PS(T) ( (unsigned long long)(T*1000000) >> 20 )

// BOOLEAN InitiatorORResponder
#define INIT_SIDE 0
#define RESP_SIDE 1

// RTT Processing structure.
typedef struct {
	UINT64 t1, t2, t3, t4;
	SINT64 Rtt;
	SINT32 cfoResp, cfoInit;
	UINT32 initPktid, respPktid;
} hal_st_WlsParams;

typedef struct {
	UINT32 dialogToken;
	UINT32 Phase_Roll;
	UINT32 FirstPathDelay;
	UINT32 pktinfo;
	UINT64 z1;
	UINT64 z2;
	UINT64 z3;
	UINT64 z4;
	UINT64 z5;
	UINT64 z6;
	//UINT64 Info_TSF;
	//UINT64 DiffTSF;
} hal_WLS_Timestamp_Info;

#define WLS_BW_20 0
#define WLS_BW_40 1
#define WLS_BW_80 2
#define WLS_BW_160 3

typedef struct hal_csirxinfo {
	// DWORD-0
	UINT32 header_length:13;
	UINT32 rsvd0:3;
	UINT32 signature:16;	// 0x0000
	// DWORD-1
	UINT32 pktinfo:20;
	UINT32 rsvd1:12;
	// DWORD-2
	UINT32 lsig:24;
	UINT32 cfo_coarse:8;
	// DWORD-3
	UINT32 htsig1:24;
	UINT32 cfo_fine:8;
	// DWORD-4
	UINT32 htsig2:24;
	UINT32 rsvd2:8;
	// DWORD-5
	UINT32 rx_rssi:8;
	UINT32 rx_noise_floor:8;
	UINT32 rsvd3:16;
	// DWORD-6
	UINT32 rx_rssi_a:8;
	UINT32 rx_rssi_b:8;
	UINT32 rx_rssi_c:8;
	UINT32 rx_rssi_d:8;
	// DWORD-7
	UINT32 rx_rssi_e:8;
	UINT32 rx_rssi_f:8;
	UINT32 rx_rssi_g:8;
	UINT32 rx_rssi_h:8;
	// DWORD-8
	UINT32 rx_nf_a:8;
	UINT32 rx_nf_b:8;
	UINT32 rx_nf_c:8;
	UINT32 rx_nf_d:8;
	// DWORD-9
	UINT32 rx_nf_e:8;
	UINT32 rx_nf_f:8;
	UINT32 rx_nf_g:8;
	UINT32 rx_nf_h:8;
	// DWORD-10
	UINT32 gain_code_11ft:24;
	UINT32 rsvd4:8;
	// DWORD-11
	UINT32 gain_code_ht:24;
	UINT32 rsvd5:8;
	// DWORD-12
	UINT32 timestamp_0;
	// DWORD-13
	UINT32 timestamp_1;
	// DWORD-14
	UINT32 timestamp_2;
	// DWORD-15
	UINT32 timestamp_3;
	// DWORD-16
	UINT32 timestamp_4;
	// DWORD-17
	UINT32 timestamp_5;
	// DWORD-18
	UINT32 timestamp_6;
	// DWORD-19
	UINT32 timestamp_7;
	// DWORD-20
	UINT32 timestamp_8;
} hal_csirxinfo_t;

#define CSI_PROCESSING_BUF_ALLOCATED   (CSI_SCRATCH_BFR_DW * 4)
// input is in 16p14
#define ONE_16P14 (1<<14)

/*typedef struct AoA_Output
{
	UINT8 MAC_address[6];
	UINT8 pkt_type;
	UINT8 pkt_subtype;
	UINT32 pkt_bb_info;
	UINT16 angle;
	UINT16 weight;
} AoA_Output_st; */

typedef struct CSI_CONFIG_st {
	// WLS / AoA Processing Input Parameters
	hal_wls_aoa_processing_input_params_t wls_aoa_processing_input_params;
	hal_wls_packet_params_t wls_packet_parameters;
	UINT32 *rx_csi_processing_buf;
	unsigned char g_packetType;
	UINT8 *csiBufferMemory;
	// RTT Processing from CSI Processed Data
	hal_st_WlsParams *WlsParams;
	int wlsDebugBufferIdx;
	UINT32 *wlsDebugBuffer;
	//AoA_Output_st* AoA_Output_Array;
#ifdef WLS_CSI_DUMP
	UINT32 *wlsCsiBuffer;
#endif
} CSI_CONFIG_st;

int hal_processCsiWls(unsigned int *fftBuffer, hal_wls_packet_params_t * packetparams, hal_wls_aoa_processing_input_params_t * inputVals,
		      int *resArray);
void programRegister(unsigned int *bufferMemoryPtr, int bufferNum);
void hal_rx_csi_processing_buf(struct net_device *netdev, evt_prdcsi_t * prdcsi_data);
void hal_rx_csi_aoa_processing(struct net_device *netdev, evt_prdcsi_t * prdcsi_data, int *CSI_Processing_Results_Array);

SINT32 hal_wls_getCalVal(UINT32 SignalBW, UINT32 DeviceBW, int chanOffset5G, UINT8 isSc5);
UINT32 hal_computeRtt(hal_st_WlsParams * WlsParams);
SINT32 hal_computeDistancefromns(hal_st_WlsParams * WlsParams);

#endif				/* AP8X_CSI_H_ */
