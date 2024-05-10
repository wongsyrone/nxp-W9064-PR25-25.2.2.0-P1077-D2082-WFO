/** @file ds.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
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
* Purpose: 
*    This file contains the function prototypes and definitions for the 
*    Distribution Service Module. 
* 
* Public Procedures: 
* 
* Notes: 
*    None. 
* 
*****************************************************************************/

#ifndef _DS_H_
#define _DS_H_
#include "wl_hal.h"
#include "StaDb.h"
#include "ap8xLnxIntf.h"
//=============================================================================
//                          PUBLIC TYPE DEFINITIONS
//=============================================================================

#define ETHER_HDR_SIZE 14
#define MAX_ETHER_PKT_SIZE 1800	//should be 0x600, need to check.

#define IS_BROADCAST(macaddr) ((*(UINT32*)macaddr == 0xffff ) &&  \
                          *(UINT16 *)((UINT8*)macaddr+4) == 0xff)

#define IS_MULTICAST(macaddr)  ((*(UINT8*)macaddr & 0x01) == 0x01)

#define MACADDR_CMP(macaddr1, macaddr2)         \
		((*(UINT32*)macaddr1 == *(UINT32*)macaddr2) && \
		(*(UINT16 *)((UINT8*)macaddr1+4) == (*(UINT16 *)((UINT8*)macaddr2+4))) ? \
		0 : 1)

#define MACADDR_CPY(macaddr1,macaddr2) { *(UINT16*)macaddr1 = *(UINT16*)macaddr2; \
                    *(UINT16 *)((UINT16*)macaddr1+1) = *(UINT16 *)((UINT16*)macaddr2+1); \
                    *(UINT16 *)((UINT16*)macaddr1+2) = *(UINT16 *)((UINT16*)macaddr2+2);}

typedef struct {
#ifdef MV_CPU_LE
	UINT8 ihl:4;		//Note that the MS nibble is Version.
	//the LS nibble is Header Length.
	UINT8 ver:4;
#else
	UINT8 ver:4;
	UINT8 ihl:4;
#endif
	UINT8 tos;
	UINT16 total_length;
	UINT16 identification;
	UINT16 flag_fragoffset;	//the MS three bits are for flag and rest is fragment offset.
	UINT8 ttl;
	UINT8 protocol;
	UINT16 header_chksum;
	UINT8 src_IP_addr[4];
	UINT8 dst_IP_addr[4];
} PACK_END IEEEtypes_IPv4_Hdr_t;

/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */
typedef struct {
#ifdef MV_CPU_LE
	UINT8 traffic_class:4;
	UINT8 ver:4;
#else
	UINT8 ver:4;
	UINT8 traffic_class:4;
#endif
	UINT8 flow_label[3];
	UINT16 payload_length;
	UINT8 next_header;
	UINT8 hop_limit;
	UINT8 src_IP_addr[4];
	UINT8 dst_IP_addr[4];
} PACK_END IEEEtypes_IPv6_Hdr_t;

typedef struct {
	UINT16 src_port;
	UINT16 dst_port;
	UINT32 seq_num;
	UINT32 ack_num;
	UINT32 datoffset_control_window;	//data offset is MS four bits
	UINT16 chksum;
	UINT16 urgent_ptr;
} PACK_END IEEEtypes_TCP_Hdr_t;

typedef struct {
	UINT16 src_port;
	UINT16 dst_port;
	UINT16 len;
	UINT16 chksum;
} PACK_END IEEEtypes_UDP_Hdr_t;

typedef struct {
	ether_hdr_t Hdr;
	UINT8 Body[1800 - ETHER_HDR_SIZE];
} PACK_END IEEEtypes_8023_Frame_t;

typedef struct {
	IEEEtypes_8023_Frame_t DataFrame;
} PACK_END rx8023_DataFrame_t;

typedef struct llc_snap_hdr {
	UINT8 Dsap;
	UINT8 Ssap;
	UINT8 Control;
	UINT8 Org[3];
	UINT16 Type;
} llc_snap_hdr_t;

typedef struct {
	UINT16 Type;
	UINT16 Control;
} IEEE802_1QTag_t;

#define IEEE802_11Q_TYPE    0x8100
#define IPV6_VERSION 0x06

// COPY from kernel include/linux/if_ether.h
#define ETH_P_IP	0x0800	/* Internet Protocol packet     */
#define ETH_P_IPV6	0x86DD	/* IPv6 over bluebook           */

extern IEEEtypes_MacAddr_t bcast;
#ifdef SOC_W906X
void free_any_pending_ampdu_pck(struct net_device *dev, UINT16 StnId);
#else
void free_any_pending_ampdu_pck(struct net_device *dev, UINT16 Aid);
#endif /* SOC_W906X */
extern void disableAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr,
			   UINT8 tid);
extern void cleanupAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr);
extern void disableAmpduTxstream(vmacApInfo_t * vmacSta_p, int stream);
extern void disableAmpduTxMacAddr(vmacApInfo_t * vmacSta_p, UINT8 * macaddr);
extern void disableAmpduTxAll(vmacApInfo_t * vmacSta_p);
#ifdef SOC_W906X
extern int ieee80211_input(struct net_device *dev, struct sk_buff *skb,
			   u_int32_t rssi, RssiPathInfo_t * rssiPaths,
			   wlrxdesc_t * pCfhul, u_int8_t isFirstMsdu,
			   u_int16_t stnid, u_int8_t LMFbit);
extern struct sk_buff *ieee80211_encap(struct sk_buff *skb,
				       struct net_device *netdev, BOOLEAN eap,
				       void *pStaInfo);
#else
extern int ieee80211_input(struct net_device *dev, struct sk_buff *skb,
			   u_int32_t rssi, u_int32_t rssiPaths,
			   u_int8_t ampdu_qos, u_int32_t status,
			   u_int16_t stnid);
extern struct sk_buff *ieee80211_encap(struct sk_buff *skb,
				       struct net_device *netdev, BOOLEAN eap);
#endif /* SOC_W906X */
extern BOOLEAN McastProxyUCastAddrRemove(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_MacAddr_t * addr);
#endif /* _DS_H_ */
