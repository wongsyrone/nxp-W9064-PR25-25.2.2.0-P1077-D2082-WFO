/** @file ap8xLnxXmit.c
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

/** include files **/
#include <linux/igmp.h>

#include "wldebug.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxFwcmd.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "StaDb.h"
#include "mlmeApi.h"
#include "wds.h"
#include "ccmp.h"
#ifdef ZERO_COPY
#undef AGG_QUE
#endif
#ifdef MRVL_WAPI
#include "wapi.h"
#endif

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/pci.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/checksum.h>
#include <net/ip.h>
#ifdef WLAN_INCLUDE_TSO
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
#define tso_size gso_size
#endif

#endif /*WLAN_INCLUDE_TSO */

#ifdef EWB
#include "ewb_packet.h"
#endif

#ifdef MPRXY
#include "ap8xLnxMPrxy.h"

#define	IS_IN_CLASSD(a)		((((UINT32) (a)) & 0xf0000000) == 0xe0000000)
#define	IS_IN_MULTICAST(a)		IS_IN_CLASSD(a)
#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP	    0x0800	/* IP protocol */
#define	ETHERTYPE_IP_NW	    0x0008	/* IP protocol network byte order */
#endif
#endif

/*WiFi pre-cert usage. Caution: Any changes here need to verify with WiFi WMM test cases. todo...*/
UINT32 qosctrl_txQLimit = 1000;
UINT8 qosctrl_mode = 0;		//to store what qos ctrl mode, 0:disable, 1:11n, 2:11ac
UINT32 qosctrl_loopcnt[4] = { 0, 0, 0, 0 };	//BK,BE,VI,VO. To cnt loop iteration per AC
UINT32 qosctrl_loopthres[2][4] = { {30, 30, 0, 40}
, {0, 0, 0, 60}
};				// 11n BK,BE,VI,VO and 11ac BK,BE,VI,VO qos ctrl loop threshold
UINT32 qosctrl_pktthres[2][4] = { {100, 150, 2000, 200}
, {0, 1000, 0, 10}
};				// 11n BK,BE,VI,VO and 11ac BK,BE,VI,VO qos pkt threshold

/** local definitions **/
#define SET_QUEUE_NUMBER(skb, pri) 	{ \
										if((skb->priority)&0x7) \
											pri = AccCategoryQ[(skb->priority)&0x7]; \
										else \
											pri=AccCategoryQ[Qos_GetDSCPPriority(skb->data)&0x7];\
									}\


#define SET_STA_QUEUE_NUMBER(skb, pri) 	{ \
						if((skb->priority)&0x7) \
							pri = QosTsData[(skb->priority)&0x7].AccCategoryQDowngrade; \
						else \
							pri = QosTsData[Qos_GetDSCPPriority(skb->data)&0x7].AccCategoryQDowngrade;\
					}\

#define CURR_TXD(i) wlpptr->wlpd_p->descData[i].pStaleTxDesc
#define	IEEE80211_ADDR_COPY(dst,src)	memcpy(dst,src,IEEEtypes_ADDRESS_SIZE)
/*
* Structure of a 10Mb/s Ethernet header.
*/
struct ether_header {
	UINT8 ether_dhost[IEEEtypes_ADDRESS_SIZE];
	UINT8 ether_shost[IEEEtypes_ADDRESS_SIZE];
	UINT16 ether_type;
};

#ifdef WDS_FEATURE
struct ieee80211_frame {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;
#endif

/** external functions **/
/** external data **/
u_int32_t debug_tcpack = 4;
/** internal functions **/
// Copy MAC Address from Src to Dst
static inline void
COPY_MAC_ADDR(u_int8_t * dst, u_int8_t * src)
{
	(*(u_int16_t *) & dst[0]) = (*(u_int16_t *) & src[0]);
	(*(u_int16_t *) & dst[2]) = (*(u_int16_t *) & src[2]);
	(*(u_int16_t *) & dst[4]) = (*(u_int16_t *) & src[4]);
}

/** public data **/

/** private data **/
/** public functions **/
#ifdef WLAN_INCLUDE_TSO
static inline void _wlDataTx(struct sk_buff *skb, struct net_device *netdev);

static inline unsigned short
ipcksum(unsigned char *ip, int len)
{
	long sum = 0;		/* assume 32 bit long, 16 bit short */

	while (len > 1) {
		sum += *((unsigned short *)ip);
		ip += 2;
		if (sum & 0x80000000)	/* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)		/* take care of left over byte */
		sum += (unsigned short)*(unsigned char *)ip;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static inline int
wlan_tso_tx(struct sk_buff *skb, struct net_device *netdev)
{
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *th = (struct tcphdr *)skb_transport_header(skb);
	unsigned int doffset = (iph->ihl + th->doff) * 4;
	unsigned int mtu = skb_shinfo(skb)->tso_size + doffset;
	unsigned int offset = 14;
	UINT32 seq = ntohl(th->seq);
	UINT16 id = ntohs(iph->id);

	while (offset + doffset < skb->len) {
		unsigned int frag_size = min(mtu, skb->len - offset) - doffset;
		struct sk_buff *nskb = wl_alloc_skb(mtu + MIN_BYTES_HEADROOM);

		if (!nskb)
			break;
		skb_reserve(nskb, MIN_BYTES_HEADROOM);
		skb_set_mac_header(nskb, -14);
		skb_set_network_header(nskb, 0);
		skb_set_transport_header(nskb, ip_hdrlen(skb));
		iph = (struct iphdr *)skb_network_header(nskb);
		memcpy(skb_mac_header(nskb), skb->data, 14);
		memcpy(nskb->data, skb_network_header(skb), doffset);
		if (skb_copy_bits(skb,
				  doffset + offset,
				  nskb->data + doffset, frag_size))
			WLDBG_INFO(DBG_LEVEL_13, "TSO BUG\n");
		skb_put(nskb, doffset + frag_size);
		nskb->ip_summed = CHECKSUM_UNNECESSARY;
		nskb->dev = skb->dev;
		nskb->priority = skb->priority;
		nskb->protocol = skb->protocol;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
		skb_dst_set(nskb, dst_clone(skb_dst(skb)));
#else
		nskb->dst = dst_clone(skb->dst);
#endif
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
		nskb->pkt_type = skb->pkt_type;

		th = (struct tcphdr *)skb_transport_header(nskb);
		iph->tot_len = htons(frag_size + doffset);
		iph->id = htons(id);
		iph->check = 0;
		iph->check = ipcksum((unsigned char *)iph, iph->ihl * 4);
		//iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
		th->seq = htonl(seq);
		if (offset + doffset + frag_size < skb->len)
			th->fin = th->psh = 0;
		th->check = 0;
		nskb->csum = skb_checksum(nskb, iph->ihl * 4,
					  nskb->len - iph->ihl * 4, 0);
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					      nskb->len - iph->ihl * 4,
					      IPPROTO_TCP, nskb->csum);
		skb_push(nskb, 14);
		_wlDataTx(nskb, netdev);
		offset += frag_size;
		seq += frag_size;
		id++;
	}

	wl_free_skb(skb);
	return 0;
}

static inline int
tcp_checksum_offload(struct sk_buff *skb, struct net_device *netdev)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + 14);
	struct tcphdr *th = (struct tcphdr *)(skb->data + 14 + (iph->ihl * 4));
	struct udphdr *udph = (struct udphdr *)th;
	if ((iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) &&
	    (htons(ETH_P_IP) == skb->protocol)) {
		/* The tcp frames from Ethernet marked by Marvell Ethernet driver as CHECKSUM_NONE 
		   because it failed the csum offload check as the size failed the minimum byte count (72) requirement.
		   The same frame was also calculated wrong with the wlan driver tcp_checksum_offload function.
		   This still needs some investigation. */
		if (skb->ip_summed == CHECKSUM_NONE ||
		    skb->ip_summed == CHECKSUM_UNNECESSARY)
			return 0;
		skb_pull(skb, 14);
		if (iph->protocol == IPPROTO_TCP) {
			th->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4,
						 skb->len - iph->ihl * 4, 0);
			th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						      skb->len - iph->ihl * 4,
						      IPPROTO_TCP, skb->csum);
		} else {
			udph->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4,
						 skb->len - iph->ihl * 4, 0);
			udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
							skb->len - iph->ihl * 4,
							IPPROTO_UDP, skb->csum);
		}
		skb_push(skb, 14);
		return 1;
	}
	return 0;
}

#endif
#ifdef TCP_ACK_ENHANCEMENT

#define WORD_SWAP(X) (((X)&0xff)<<24)+      \
                    (((X)&0xff00)<<8)+      \
                    (((X)&0xff0000)>>8)+    \
                    (((X)&0xff000000)>>24)

int
get_tcp_ack_sequence_no(struct sk_buff *skb, u_int32_t * seq)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + 14);
	struct tcphdr *th = (struct tcphdr *)(skb->data + 14 + (iph->ihl * 4));
	if ((iph->protocol == IPPROTO_TCP) &&
	    (htons(ETH_P_IP) == skb->protocol)) {
		if ((th->ack == 1) &&
		    (htons(iph->tot_len) == (iph->ihl * 4 + th->doff * 4))) {

			if (th->syn || th->fin) {
				//do not mark syn and fin as drop cadidate
				skb->cb[1] = 0;
				return 0;
			}

			{
				*((u_int32_t *) & skb->cb[4]) =
					WORD_SWAP(th->ack_seq);
				*((u_int32_t *) & skb->cb[8]) =
					th->source | (th->dest << 16);
				skb->cb[1] = 2;	//"consider" to be drop in fw  
				*seq = th->ack_seq;

				return 1;
			}
		}
	}
	skb->cb[1] = 0;
	return 0;
}
#endif

int
wlDataTx(struct sk_buff *skb, struct net_device *netdev)
{
	UINT8 Priority;
	UINT32 txqlimit;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *wlpptrvmac = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef QUEUE_STATS_CNT_HIST
	struct ether_header *pEth;
#endif

#ifdef MRVL_DFS
	DfsAp *pdfsApMain = NULL;
#endif //MRVL_DFS

	BOOLEAN delskb = FALSE;	//Used in mcast proxy to mark original skb to be dropped 
	BOOLEAN skbCopyError = FALSE;
	BOOLEAN schedulepkt = FALSE;	//Schedule tx only when queue to txq. Dropped pkt won't be scheduled

#ifdef MPRXY
	vmacApInfo_t *vmacSta_p = wlpptrvmac->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	UINT32 i;
	UINT8 IPMcastGrpIndex = 0xFF;
	struct sk_buff *skbCopy = NULL;
	struct ether_header *pEthHdr = NULL;
	struct ether_header *pEthHdrMcast = NULL;
	IEEEtypes_IPv4_Hdr_t *IPv4_p = NULL;
	IEEEtypes_IPv6_Hdr_t *IPv6_p = NULL;
	UINT32 dIPAddr = 0;
	struct iphdr *ipheader = NULL;
	struct igmphdr *igmpheader = NULL;
#endif

	txqlimit = priv->vmacSta_p->txQLimit;
	if (qosctrl_mode)
		txqlimit = qosctrl_txQLimit;

	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

	/* QUEUE_STATS: time stamp the start time of the packet */
	WLDBG_SET_PKT_TIMESTAMP(skb);
#ifdef QUEUE_STATS_CNT_HIST
	pEth = (struct ether_header *)skb->data;
	/* track per sta tx count */
	wldbgRecPerStatxPktStats(pEth->ether_dhost, QS_TYPE_TX_EN_Q_CNT);
#endif

#ifdef MRVL_DFS
	pdfsApMain = wlpptr->wlpd_p->pdfsApMain;
	if (pdfsApMain && pdfsApMain->dropData) {
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_dropped++;
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_carrier_errors++;

		/* QUEUE_STATS:  count packets drop due to DFS */
		WLDBG_INC_DFS_DROP_CNT(AccCategoryQ[(skb->priority) & 0x7]);

		wl_free_skb(skb);
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: DFS", netdev->name);
		return 0;
	}
#endif //MRVL_DFS
	if ((netdev->flags & IFF_RUNNING) == 0) {
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_dropped++;
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_carrier_errors++;

		/* QUEUE_STATS:  count packets drop due to interface is not running */
		WLDBG_INC_IFF_DROP_CNT(AccCategoryQ[(skb->priority) & 0x7]);

		wl_free_skb(skb);
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: itf not running",
				netdev->name);
		return 0;
	}

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA)
		SET_QUEUE_NUMBER(skb, Priority)
			else
		SET_STA_QUEUE_NUMBER(skb, Priority)
//#ifndef NEW_DP
			if (skb_queue_len(&wlpptr->wlpd_p->txQ[Priority]) >
			    txqlimit) {
			/* QUEUE_STATS:  count packets drop due to queue full */
			WLDBG_INC_TXQ_DROP_CNT(Priority);

#ifdef QUEUE_STATS_CNT_HIST
			/* track per sta tx count */
			wldbgRecPerStatxPktStats(pEth->ether_dhost,
						 QS_TYPE_TX_Q_DROPE_CNT);
#endif
			wl_free_skb(skb);
			((NETDEV_PRIV_P(struct wlprivate, netdev)))->
				netDevStats.tx_dropped++;

			WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: qlen > limit",
					netdev->name);
			return 0;	//Can return since we don't need new incoming pkt flush out pkts stuck in txq. timer_routine will flush out stuck pkts in txq
		} else
//#endif /* NEW_DP */
		{
#ifdef MPRXY
			/*Move mcast proxy from _wlDataTx to wlDataTx so we only queue pkts to be sent into txq, not all incoming pkts.
			 * This eliminates unnecessary mcast pkt going into txq and will save txq buffer from being occupied by 
			 * these unnecesary pkts which are eventually dropped later.
			 */
			if (*(mib->mib_MCastPrxy) &&
			    (vmacSta_p->VMacEntry.modeOfService !=
			     VMAC_MODE_CLNT_INFRA)) {
				dIPAddr = 0;
				ipheader =
					(struct iphdr *)((UINT8 *) pEth +
							 sizeof(ether_hdr_t));

				/* Get the pointer to the IGMP header and its data */
				if (ipheader->protocol == IPPROTO_IGMP)
					igmpheader =
						(struct igmphdr *)((UINT8 *)
								   ipheader +
								   ipheader->
								   ihl * 4);

				/* check if IP packet, locate IP header check if IP address is multicast */
				if ((pEth->ether_type ==
				     (UINT16) ETHERTYPE_IP_NW &&
				     IS_GROUP((UINT8 *) & (pEth->ether_dhost))
				     && (ipheader->protocol != IPPROTO_IGMP)) ||
				    (pEth->ether_type ==
				     (UINT16) ETHERTYPE_IP_NW &&
				     IS_GROUP((UINT8 *) & (pEth->ether_dhost))
				     && (ipheader->protocol == IPPROTO_IGMP) &&
				     igmpheader->type ==
				     IGMP_HOST_MEMBERSHIP_QUERY)) {
					IPv4_p = (IEEEtypes_IPv4_Hdr_t
						  *) ((UINT8 *) pEth +
						      sizeof(ether_hdr_t));

					dIPAddr =
						WORD_SWAP(*
							  ((UINT32 *) IPv4_p->
							   dst_IP_addr));

					//check if the pkt is IPv4 or IPV6
					if (IPv4_p->ver == IPV6_VERSION) {
						IPv6_p = (IEEEtypes_IPv6_Hdr_t
							  *) IPv4_p;
						dIPAddr =
							WORD_SWAP(*
								  ((UINT32 *)
								   IPv6_p->
								   dst_IP_addr));
					}
				} else if (ipheader->protocol == IPPROTO_IGMP &&
					   ((igmpheader->type ==
					     IGMP_HOST_MEMBERSHIP_REPORT) ||
					    (igmpheader->type ==
					     IGMPV2_HOST_MEMBERSHIP_REPORT) ||
					    (igmpheader->type ==
					     IGMPV3_HOST_MEMBERSHIP_REPORT))) {
					delskb = TRUE;

					/* IGMP reports are not forwarded to all wireless clients */
					goto schedule;
				}
			}
			/*for mDNS etc, 224.0.0.x local group shall be sent out as is since the group */
			/* would not be created at the first place */
			if (*(mib->mib_MCastPrxy) && IS_IN_MULTICAST(dIPAddr) &&
			    !LOCAL_MCAST(WORD_SWAP(dIPAddr))) {
				/* Check if IPM address exists in IPM filter address list */
				/* if the address is present in the list then do not proxy */
				for (i = 0;
				     i < *(mib->mib_IPMFilteredAddressIndex);
				     i++) {
					/* Do not proxy, just schedule for tx */
					if (dIPAddr ==
					    *(mib->mib_IPMFilteredAddress[i])) {
						/* QUEUE_STATS:  count packets successfully enqueue to TxQ */
						WLDBG_INC_TX_OK_CNT(skb,
								    Priority);
						WLDBG_REC_TX_Q_DEPTH(wlpptr->
								     wlpd_p->
								     txQ
								     [Priority].
								     qlen,
								     Priority);
						skb->dev = netdev;
						skb_queue_tail(&wlpptr->wlpd_p->
							       txQ[Priority],
							       skb);
						schedulepkt = TRUE;
						goto schedule;
					}
				}

				/* check if IP packet, locate IP header, check if IP address is multicast */
				/* determine if IP multicast group address is in IP multicast group tables */
				for (i = 0; i < *(mib->mib_IPMcastGrpCount);
				     i++) {
					if (dIPAddr ==
					    mib->mib_IPMcastGrpTbl[i]->
					    mib_McastIPAddr) {
						/* store the index of this multicast group */
						IPMcastGrpIndex = i;
						break;
					}
				}

				pEthHdrMcast = (struct ether_header *)skb->data;
				if ((IPMcastGrpIndex != 0xFF) &&
				    IPMcastGrpIndex < MAX_IP_MCAST_GRPS) {
					if (skb != NULL) {
						for (i = 0;
						     i <
						     mib->
						     mib_IPMcastGrpTbl
						     [IPMcastGrpIndex]->
						     mib_MAddrCount; i++) {
							/* First look up the the unicast address in the station database */
							/*Compare eth source addr with UCastAddr in list to prevent received multicast pkt from client from being converted to unicast */
							/*Received multicast pkt from client should be sent out in wlan and eth as it is */
							if (((extStaDb_GetStaInfo(vmacSta_p, &(mib->mib_IPMcastGrpTbl[IPMcastGrpIndex]->mib_UCastAddr[i]), 1)) != NULL)
							    &&
							    !(memcmp
							      ((char *)&mib->
							       mib_IPMcastGrpTbl
							       [IPMcastGrpIndex]->
							       mib_UCastAddr[i],
							       (char *)
							       pEthHdrMcast->
							       ether_shost,
							       6) == 0)) {
								/* make a copy of the original skb */
								skbCopy =
									skb_copy
									(skb,
									 GFP_ATOMIC);

								if (skbCopy ==
								    NULL) {
									delskb = TRUE;
									skbCopyError
										=
										TRUE;
									goto schedule;
								}

								/* update the destination address from multicast to unicast */
								pEthHdr =
									(struct
									 ether_header
									 *)
									skbCopy->
									data;
								IEEE80211_ADDR_COPY
									(&
									 (pEthHdr->
									  ether_dhost),
									 mib->
									 mib_IPMcastGrpTbl
									 [IPMcastGrpIndex]->
									 mib_UCastAddr
									 [i]);

								/* QUEUE_STATS:  count packets successfully enqueue to TxQ */
								WLDBG_INC_TX_OK_CNT
									(skbCopy,
									 Priority);
								WLDBG_REC_TX_Q_DEPTH
									(wlpptr->
									 wlpd_p->
									 txQ
									 [Priority].
									 qlen,
									 Priority);
								skbCopy->dev =
									netdev;
								skb_queue_tail
									(&wlpptr->
									 wlpd_p->
									 txQ
									 [Priority],
									 skbCopy);
								schedulepkt =
									TRUE;
							}
						}
						delskb = TRUE;
						goto schedule;
					}
					delskb = TRUE;
					goto schedule;
				} else {
					delskb = TRUE;
					goto schedule;
				}
			} else
#endif /* MPRXY */
			{
				/* QUEUE_STATS:  count packets successfully enqueue to TxQ */
				WLDBG_INC_TX_OK_CNT(skb, Priority);
				WLDBG_REC_TX_Q_DEPTH(wlpptr->wlpd_p->
						     txQ[Priority].qlen,
						     Priority);
				skb->dev = netdev;
#ifdef TCP_ACK_ENHANCEMENT
				{
					UINT32 seq = 0;

					get_tcp_ack_sequence_no(skb, &seq);
				}
#endif
				skb_queue_tail(&wlpptr->wlpd_p->txQ[Priority],
					       skb);
				schedulepkt = TRUE;
			}
		}

schedule:

	if (delskb && skb) {
#ifdef QUEUE_STATS_CNT_HIST
		/* track per sta tx count */
		wldbgRecPerStatxPktStats(pEth->ether_dhost,
					 QS_TYPE_TX_Q_DROPE_CNT);
#endif
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_dropped++;
		/* QUEUE_STATS:  count packets drop due to error 
		 * Mcat pkt dropped due to not inside mcast proxy list is not counted because it is not an error.
		 */
		if (skbCopyError)
			WLDBG_INC_TX_ERROR_CNT(AccCategoryQ
					       [(skb->priority) & 0x7]);

		wl_free_skb(skb);
	}

	/*We don't schedule task for every pkt. Only schedule task when it is not scheduled yet. 
	 * timer_routine helps flush out all txq when no new incoming pkt by scheduling task. This also prevent pkts sitting inside txq forever 
	 * (wlDataTxHdl may not be able to send all pkts in one interupt)
	 */
	if (schedulepkt && !wlpptr->wlpd_p->isTxTaskScheduled) {
#ifdef USE_TASKLET
		tasklet_schedule(&wlpptr->wlpd_p->txtask);
#else
		schedule_work(&wlpptr->wlpd_p->txtask);
#endif
		wlpptr->wlpd_p->isTxTaskScheduled = 1;
	}
#else
	static struct tq_struct txtask;
	struct tq_struct *ptask = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);
#ifdef MRVL_DFS
	pdfsApMain = wlpptr->wlpd_p->pdfsApMain;
	if (pdfsApMain && pdfsApMain->dropData) {
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_dropped++;
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_carrier_errors++;
		wl_free_skb(skb);
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: DFS", netdev->name);
		return 0;
	}
#endif //MRVL_DFS
	if ((netdev->flags & IFF_RUNNING) == 0) {
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_dropped++;
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.
			tx_carrier_errors++;
		wl_free_skb(skb);
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: itf not running",
				netdev->name);
		return 0;
	}
	SET_QUEUE_NUMBER(skb, Priority);
	if (wlpptr->wlpd_p->txQ[Priority].qlen > txqlimit) {
		wl_free_skb(skb);
		wlpptr->netDevStats.tx_dropped++;
		return 0;
	}

	skb->dev = netdev;
	skb_queue_tail(&wlpptr->wlpd_p->txQ[Priority], skb);

	txtask.routine = wlDataTxHdl;
	txtask.data = (void *)wlpptr->netDev;
	ptask = &txtask;

	queue_task(ptask, &tq_immediate);

	if (in_interrupt()) {
		mark_bh(IMMEDIATE_BH);
	}

	return 0;
}

#ifdef MULTI_AP_SUPPORT
extern MultiAP_4Addrr_Table_t fourAddrTable;
extern MultiAP_4Addrr_Table_t fourAddrTableSTA;
#endif
static inline void
_wlDataTx(struct sk_buff *skb, struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	unsigned long flags;
	struct ether_header *pEth;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	UINT32 bcast = 0;
	BOOLEAN eapolPkt = FALSE;
#if 0
//#ifdef MPRXY                          
//Move mcast proxy to wlDataTx
	UINT32 i;
	UINT8 IPMcastGrpIndex = 0xFF;
	struct sk_buff *skbCopy = NULL;
	struct ether_header *pEthHdr = NULL;
	struct ether_header *pEthHdrMcast = NULL;
	IEEEtypes_IPv4_Hdr_t *IPv4_p = NULL;
	IEEEtypes_IPv6_Hdr_t *IPv6_p = NULL;
	UINT32 dIPAddr = 0;
	struct iphdr *ipheader = NULL;
	struct igmphdr *igmpheader = NULL;
#endif

	WLDBG_ENTER(DBG_LEVEL_13);

	// Multiple devices using the same queue.
	netdev = skb->dev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacSta_p = wlpptr->vmacSta_p;
	mib = vmacSta_p->Mib802dot11;
	pStaInfo = NULL;
	pEth = (struct ether_header *)skb->data;
#ifdef WDS_FEATURE
	if (netdev == wlpptr->netDev) {
#endif
#ifdef EWB
		if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			if (!*(mib->mib_STAMacCloneEnable)) {
				/* LAN recv of EWB */
#ifdef MULTI_AP_SUPPORT
				if (((!
				      (mib->
				       multi_ap_attr &
				       MAP_ATTRIBUTE_BACKHAUL_BSS)) &&
				     (!(mib->
					multi_ap_attr &
					MAP_ATTRIBUTE_BACKHAUL_STA))) ||
				    (pStaInfo &&
				     pStaInfo->MultiAP_4addr == 0)) {
#endif
					if (ewbLanRecv
					    (skb, vmacSta_p->macStaAddr)) {
						goto error1;
					}
#ifdef MULTI_AP_SUPPORT
				} else {
					UINT8 found = 0;
					MultiAP_4Addr_Entry_t *entry;

					// This fourAddrTable for STA mode is used for restoring the SA of Tx
					// which will be used as a lookup table for dropping packet
					found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) pEth->ether_shost, &entry, 1);

					if (found == 1) {
						MACADDR_CPY(entry->tar,
							    pEth->ether_dhost);
					} else {
						FourAddr_AddHashEntry(&entry,
								      (IEEEtypes_MacAddr_t
								       *) pEth->
								      ether_dhost,
								      (IEEEtypes_MacAddr_t
								       *) pEth->
								      ether_shost);
					}
				}
#endif
			}
		}
#endif
		if (!IS_GROUP((UINT8 *) & (pEth->ether_dhost))) {
#ifndef STADB_IN_CACHE
			int stadb_flag = STADB_UPDATE_AGINGTIME;
#else
			int stadb_flag =
				STADB_FIND_IN_CACHE | STADB_UPDATE_CACHE |
				STADB_UPDATE_AGINGTIME;
#endif /* STADB_IN_CACHE */

			pStaInfo =
				extStaDb_GetStaInfo(wlpptr->vmacSta_p,
						    &(pEth->ether_dhost),
						    stadb_flag);
#ifdef MULTI_AP_SUPPORT
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP
			    && (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)
			    && pStaInfo == NULL) {
				UINT8 bssId[6];
				UINT8 found = 0;
				MultiAP_4Addr_Entry_t *entry;

				found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) pEth->ether_dhost, &entry, 0);

				if (found == 1) {
					MACADDR_CPY(bssId, entry->tar);
					pStaInfo =
						extStaDb_GetStaInfo(wlpptr->
								    vmacSta_p,
								    (IEEEtypes_MacAddr_t
								     *) &
								    bssId[0],
								    stadb_flag);
					if (pStaInfo == NULL)
						printk("_wlDataTx: Error!!!\n");
				} else {
					//printk("_wlDataTx: target mac not found!!!\n");
				}
			}
#endif
			bcast = 0;
		} else
			bcast = 1;

#ifdef MRV_8021X
		if (pStaInfo != NULL) {
			//if (!pStaInfo->keyMgmtStateInfo.RSNDataTrafficEnabled)
#ifdef MRVL_WAPI
			eapolPkt = ((pEth->ether_type == IEEE_ETHERTYPE_PAE) ||
				    (pEth->ether_type ==
				     ETH_P_WAPI)) ? TRUE : FALSE;
#else
			eapolPkt =
				(pEth->ether_type ==
				 IEEE_ETHERTYPE_PAE) ? TRUE : FALSE;
#endif
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				// Added for fixing Centrino connectivity issue, check relevant only in AP mode
				if ((mib->Privacy->RSNEnabled) &&
				    (pStaInfo->keyMgmtStateInfo.
				     RSNDataTrafficEnabled == 0)
				    && (eapolPkt == FALSE))
					goto error1;
			}
		}
#endif

#ifdef WDS_FEATURE
	} else {
#ifdef CLIENT_SUPPORT
		if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
#endif
			// Check for WDS port
			if (!*(wlpptr->vmacSta_p->Mib802dot11->mib_wdsEnable) ||
			    ((pStaInfo = updateWds(netdev)) == NULL))
				goto error;
#ifdef CLIENT_SUPPORT
		}
#endif
	}
#endif
#ifdef CLIENT_SUPPORT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		pStaInfo =
			extStaDb_GetStaInfo(vmacSta_p,
					    (IEEEtypes_MacAddr_t *)
					    GetParentStaBSSID(vmacSta_p->
							      VMacEntry.
							      phyHwMacIndx), 1);
#ifdef MRVL_WPS_CLIENT
#ifdef MRVL_WAPI
		eapolPkt = ((pEth->ether_type == IEEE_ETHERTYPE_PAE) ||
			    (pEth->ether_type == ETH_P_WAPI)) ? TRUE : FALSE;
#else
		eapolPkt =
			(pEth->ether_type == IEEE_ETHERTYPE_PAE) ? TRUE : FALSE;
#endif
		/* The 2-way WPA Group key exchange eapol packets must be encrypted */
		if (pStaInfo &&
		    pStaInfo->keyMgmtStateInfo.RSNDataTrafficEnabled &&
		    eapolPkt) {
			eapolPkt = FALSE;
		}
#endif //MRVL_WPS_CLIENT
	}
#endif

#if 0
//#ifdef MPRXY                  
//Move mcast proxy to wlDataTx 

	if (*(mib->mib_MCastPrxy) &&
	    (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA)) {
		dIPAddr = 0;
		ipheader =
			(struct iphdr *)((UINT8 *) pEth + sizeof(ether_hdr_t));

		/* Get the pointer to the IGMP header and its data */
		if (ipheader->protocol == IPPROTO_IGMP)
			igmpheader =
				(struct igmphdr *)((UINT8 *) ipheader +
						   ipheader->ihl * 4);

		/* check if IP packet, locate IP header check if IP address is multicast */
		if ((pEth->ether_type == (UINT16) ETHERTYPE_IP_NW &&
		     IS_GROUP((UINT8 *) & (pEth->ether_dhost))
		     && (ipheader->protocol != IPPROTO_IGMP)) ||
		    (pEth->ether_type == (UINT16) ETHERTYPE_IP_NW &&
		     IS_GROUP((UINT8 *) & (pEth->ether_dhost))
		     && (ipheader->protocol == IPPROTO_IGMP) &&
		     igmpheader->type == IGMP_HOST_MEMBERSHIP_QUERY)) {
			IPv4_p = (IEEEtypes_IPv4_Hdr_t *) ((UINT8 *) pEth +
							   sizeof(ether_hdr_t));

			dIPAddr = WORD_SWAP(*((UINT32 *) IPv4_p->dst_IP_addr));

			//check if the pkt is IPv4 or IPV6
			if (IPv4_p->ver == IPV6_VERSION) {
				IPv6_p = (IEEEtypes_IPv6_Hdr_t *) IPv4_p;
				dIPAddr =
					WORD_SWAP(*
						  ((UINT32 *) IPv6_p->
						   dst_IP_addr));
			}
		} else if (ipheader->protocol == IPPROTO_IGMP &&
			   ((igmpheader->type == IGMP_HOST_MEMBERSHIP_REPORT) ||
			    (igmpheader->type == IGMPV2_HOST_MEMBERSHIP_REPORT)
			    || (igmpheader->type ==
				IGMPV3_HOST_MEMBERSHIP_REPORT))) {
			/* IGMP reports are not forwarded to all wireless clients */
			goto error;
		}
	}

	if (*(mib->mib_MCastPrxy) && IS_IN_MULTICAST(dIPAddr)) {
		/* Check if IPM address exists in IPM filter address list */
		/* if the address is present in the list then do not proxy */
		for (i = 0; i < *(mib->mib_IPMFilteredAddressIndex); i++) {
			if (dIPAddr == *(mib->mib_IPMFilteredAddress[i])) {
				/* Do not proxy, follow normal data path */
				goto normalpath;
			}

		}

		/* check if IP packet, locate IP header, check if IP address is multicast */
		/* determine if IP multicast group address is in IP multicast group tables */
		for (i = 0; i < *(mib->mib_IPMcastGrpCount); i++) {
			if (dIPAddr ==
			    mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr) {
				/* store the index of this multicast group */
				IPMcastGrpIndex = i;
				break;
			}
		}

		pEthHdrMcast = (struct ether_header *)skb->data;
		if ((IPMcastGrpIndex != 0xFF) &&
		    IPMcastGrpIndex < MAX_IP_MCAST_GRPS) {
			if (skb != NULL) {
				for (i = 0;
				     i <
				     mib->mib_IPMcastGrpTbl[IPMcastGrpIndex]->
				     mib_MAddrCount; i++) {
					/* First look up the the unicast address in the station database */
					/*Compare eth source addr with UCastAddr in list to prevent received multicast pkt from client from being converted to unicast */
					/*Received multicast pkt from client should be sent out in wlan and eth as it is */
					if (((extStaDb_GetStaInfo
					      (vmacSta_p,
					       &(mib->
						 mib_IPMcastGrpTbl
						 [IPMcastGrpIndex]->
						 mib_UCastAddr[i]), 1)) != NULL)
					    &&
					    !(memcmp
					      ((char *)&mib->
					       mib_IPMcastGrpTbl
					       [IPMcastGrpIndex]->
					       mib_UCastAddr[i],
					       (char *)pEthHdrMcast->
					       ether_shost, 6) == 0)) {
						/* make a copy of the original skb */
						skbCopy =
							skb_copy(skb,
								 GFP_ATOMIC);

						if (skbCopy == NULL)
							goto error;

						/* update the destination address from multicast to unicast */
						pEthHdr =
							(struct ether_header *)
							skbCopy->data;
						IEEE80211_ADDR_COPY(&
								    (pEthHdr->
								     ether_dhost),
								    mib->
								    mib_IPMcastGrpTbl
								    [IPMcastGrpIndex]->
								    mib_UCastAddr
								    [i]);

						wlDataTx(skbCopy, netdev);
					}
				}
				goto error;
			}
			goto error;
		} else
			goto error;
	}
normalpath:
#endif /* MPRXY */
	if ((skb = ieee80211_encap(skb, netdev, eapolPkt)) == NULL) {
		goto error;
	}

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);

	if (wlxmit(netdev, skb, IEEE_TYPE_DATA, pStaInfo, bcast, eapolPkt)) {
		WLDBG_INFO(DBG_LEVEL_13, "could not xmit");
		wlpptr->netDevStats.tx_errors++;
		netif_stop_queue(netdev);
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
		wlTxDone(netdev);
		goto error1;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	WLDBG_EXIT(DBG_LEVEL_13);
#define TXDONE_THRESHOLD 4	/*64 */
	if (wlpptr->wlpd_p->txDoneCnt++ > TXDONE_THRESHOLD) {
		wlTxDone(netdev);
		wlpptr->wlpd_p->txDoneCnt = 0;
	}

	return;

error:
error1:
	if (skb) {
		/* QUEUE_STATS:  count packets drop due to error */
		WLDBG_INC_TX_ERROR_CNT(AccCategoryQ[(skb->priority) & 0x7]);

#ifdef AMSDU_AGGREQ_FOR_8K
		if (skb->truesize > MAX_AGGR_SIZE) {
			skb_queue_tail(&wlpptr->wlpd_p->aggreQ, skb);
		} else
#endif
			wl_free_skb(skb);
	}
#ifndef NEW_DP
	{
		writel(MACREG_H2ARIC_BIT_PPA_READY,
		       wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
	}
#endif
	WLDBG_EXIT_INFO(DBG_LEVEL_13, NULL);
	return;

}

void
wlDataTxHdl(struct net_device *netdev)
{
	UINT8 num = NUM_OF_DESCRIPTOR_DATA;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct sk_buff *skb;
	u_int32_t cnt, index;

	WLDBG_ENTER(DBG_LEVEL_13);

	if (wlpptr->wlpd_p->bfwreset)
		return;
	while (num--) {
		index = num;
		if (qosctrl_mode && num < 4)
			index = 0;	//Needed in WiFi pre-cert. Only fwDescCnt[0] incremented in wlxmit, no need to check all other num??

		/**  since f/w is slower than host cpu, the while loop below might get stuck,
 one way to fix this is to interrupt f/w to fetch packet when fwowndescriptor is max **/

		if (wlpptr->wlpd_p->fwDescCnt[index] >= MAX_NUM_TX_DESC) {
#ifndef NEW_DP
			writel(MACREG_H2ARIC_BIT_PPA_READY,
			       wlpptr->ioBase1 +
			       MACREG_REG_H2A_INTERRUPT_EVENTS);
#endif
			wlTxDone(netdev);
			wlpptr->wlpd_p->txDoneCnt = 0;
		}

		if (qosctrl_mode && num < 4) {
			qosctrl_loopcnt[num]++;
			/*Number of loop to skip tx according to AC */
			if (qosctrl_loopcnt[num] >
			    qosctrl_loopthres[qosctrl_mode - 1][num])
				qosctrl_loopcnt[num] = 0;
			else
				continue;	//skip tx

		}
		cnt = 0;

		while (wlpptr->wlpd_p->fwDescCnt[index] < MAX_NUM_TX_DESC &&
		       (skb = skb_dequeue(&wlpptr->wlpd_p->txQ[num])) != 0) {
#ifdef WLAN_INCLUDE_TSO
			/* The following code is not needed since this condition is checked for and handled in the kernel and this check should never return TRUE.
			   if(skb_shinfo(skb)->frag_list != NULL)
			   {
			   printk("wlan Warning: skb->frag_list != NULL\n");
			   }
			 */
			if (skb_shinfo(skb)->tso_size) {
				wlpptr->wlpd_p->privStats.tsoframecount++;
				wlan_tso_tx(skb, netdev);
			} else {
				tcp_checksum_offload(skb, netdev);
#else
			{
#endif /* WLAN_INCLUDE_TSO */

				_wlDataTx(skb, netdev);

				if (qosctrl_mode && (num < 4)) {
					cnt++;
					if (cnt >=
					    qosctrl_pktthres[qosctrl_mode -
							     1][num])
						break;	//stop tx if exceed pkt threshold for a particular AC
				}

			}
		}
	}

	// Reset        after tx task is done
	wlpptr->wlpd_p->isTxTaskScheduled = 0;
}

int
wlMgmtTx(struct sk_buff *skb, struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned long flags;

	WLDBG_ENTER(DBG_LEVEL_13);

	/* Bypass this check for interface running when a scan is in progress */
	if (!wlpptr->vmacSta_p->busyScanning) {
		if ((netdev->flags & IFF_RUNNING) == 0) {
			wlpptr->netDevStats.tx_dropped++;
			WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: itf not running",
					netdev->name);
			return -ENETDOWN;
		}
	}

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	if (wlxmit(netdev, skb, IEEE_TYPE_MANAGEMENT, NULL, 0, FALSE)) {
		WLDBG_INFO(DBG_LEVEL_13, "could not xmit");
		wlpptr->netDevStats.tx_errors++;
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
		wlTxDone(netdev);
		goto error;
	}

	wlpptr->netDevStats.tx_packets++;
	wlpptr->netDevStats.tx_bytes += skb->len;

	/* update physical interface counter for IEEE_TYPE_MANAGEMENT */
	if (wlpptr->master) {
		((NETDEV_PRIV_P(struct wlprivate, wlpptr->master)))->
			netDevStats.tx_packets++;
		((NETDEV_PRIV_P(struct wlprivate, wlpptr->master)))->
			netDevStats.tx_bytes += skb->len;
	}

	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	WLDBG_EXIT(DBG_LEVEL_13);
	return 0;

error:
	if (skb) {
		wl_free_skb(skb);
	}
	WLDBG_EXIT_INFO(DBG_LEVEL_13, NULL);
	return 0;

}

#ifdef NEW_DP

#ifdef ENABLE_MONIF
/* please refer to struct wlprivate to know the number */
#define EXTRA_VMAC_NR   2
#else
#define EXTRA_VMAC_NR   1
#endif

#ifdef __aarch64__
static u32
wlxmit_set_tx_skb(struct wlprivate *wlpptr, struct sk_buff *skb)
{
	u32 idx = wlpptr->wlpd_p->descData[0].Tx_vBufList_idx;

	while (wlpptr->wlpd_p->descData[0].Tx_vBufList[idx]) {
		idx = (idx + 1) % (wlpptr->wlpd_p->TxDescLimit);
	}
	wlpptr->wlpd_p->descData[0].Tx_vBufList_idx =
		(idx + 1) % (wlpptr->wlpd_p->TxDescLimit);
	wlpptr->wlpd_p->descData[0].Tx_vBufList[idx] = skb;

	return idx;
}

static u32
wlxmit_reset_and_free_tx_skb(struct wlprivate *wlpptr,
			     tx_ring_done_t * pTxRingDone)
{
	struct sk_buff *skb;

	if (pTxRingDone->User >= wlpptr->wlpd_p->TxDescLimit) {
		/* might need a counter to record the events */
		return 1;
	}

	skb = wlpptr->wlpd_p->descData[0].Tx_vBufList[pTxRingDone->User];
	wlpptr->wlpd_p->descData[0].Tx_vBufList[pTxRingDone->User] = NULL;

	if (skb) {
		wl_free_skb(skb);
		pTxRingDone->User = 0;
		return 0;
	} else
		return 1;
}
#endif

UINT32 DoneCnt = 0;
void
wlTxDone(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned long flags;
	UINT32 txDoneTail;
	UINT32 txDoneHead, txDoneHeadnew;
	tx_ring_done_t *pTxRingDone;

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	txDoneHeadnew = readl(wlpptr->ioBase1 + MACREG_REG_TxDoneHead);
	txDoneTail =
		wlpptr->wlpd_p->descData[0].
		TxDoneTail & (MAX_TX_RING_DONE_SIZE - 1);
	txDoneHead = txDoneHeadnew & (MAX_TX_RING_DONE_SIZE - 1);
	while (txDoneHead != txDoneTail) {
		pTxRingDone =
			&wlpptr->wlpd_p->descData[0].pTxRingDone[txDoneTail];

#ifdef __aarch64__
		if (wlxmit_reset_and_free_tx_skb(wlpptr, pTxRingDone)) {
#else
		if (pTxRingDone && pTxRingDone->User) {
			//skb_unlink((struct sk_buff *)pTxRingDone->User,&wlpptr->wlpd_p->txQueRecord); 
			wl_free_skb((struct sk_buff *)pTxRingDone->User);
			pTxRingDone->User = 0;
		} else {
#endif
			if (++txDoneTail >= MAX_TX_RING_DONE_SIZE) {
				txDoneTail = 0;
			}
			if (wlpptr->wlpd_p->descData[0].txDescBusyCnt > 0)
				wlpptr->wlpd_p->descData[0].txDescBusyCnt--;
			//decrement legacy counters to prevent tx stop
			if (wlpptr->wlpd_p->fwDescCnt[0]-- <= 0)
				wlpptr->wlpd_p->fwDescCnt[0] = 0;
			if (wlpptr->wlpd_p->fwDescCnt[1]-- <= 0)
				wlpptr->wlpd_p->fwDescCnt[1] = 0;
			if (wlpptr->wlpd_p->fwDescCnt[2]-- <= 0)
				wlpptr->wlpd_p->fwDescCnt[2] = 0;
			if (wlpptr->wlpd_p->fwDescCnt[3]-- <= 0)
				wlpptr->wlpd_p->fwDescCnt[3] = 0;
			break;
		}
		//decrement legacy counters to prevent tx stop
		if (wlpptr->wlpd_p->fwDescCnt[0]-- <= 0)
			wlpptr->wlpd_p->fwDescCnt[0] = 0;
		if (wlpptr->wlpd_p->fwDescCnt[1]-- <= 0)
			wlpptr->wlpd_p->fwDescCnt[1] = 0;
		if (wlpptr->wlpd_p->fwDescCnt[2]-- <= 0)
			wlpptr->wlpd_p->fwDescCnt[2] = 0;
		if (wlpptr->wlpd_p->fwDescCnt[3]-- <= 0)
			wlpptr->wlpd_p->fwDescCnt[3] = 0;

		if (++txDoneTail >= MAX_TX_RING_DONE_SIZE) {
			txDoneTail = 0;
		}
		if (wlpptr->wlpd_p->descData[0].txDescBusyCnt > 0)
			wlpptr->wlpd_p->descData[0].txDescBusyCnt--;
		//txDoneHeadnew = (txDoneHeadnew&~(MAX_TX_RING_DONE_SIZE-1)|txDoneHead);
	}
	writel(txDoneTail, wlpptr->ioBase1 + MACREG_REG_TxDoneTail);
	wlpptr->wlpd_p->descData[0].TxDoneTail = txDoneTail;

	if (wlpptr->wlpd_p->descData[0].txDescBusyCnt <
	    (wlpptr->wlpd_p->TxDescLimit - 1)) {
		if (!wlpptr->master) {
			int mbss_idx = 0;

			if (netif_running(netdev) &&
			    netif_queue_stopped(netdev))
				netif_wake_queue(netdev);

			for (mbss_idx = 0;
			     mbss_idx < MAX_VMAC_INSTANCE_AP + EXTRA_VMAC_NR;
			     mbss_idx++) {
				struct net_device *netdev_v =
					wlpptr->vdev[mbss_idx];

				if (netdev_v) {
					if (netif_running(netdev_v) &&
					    netif_queue_stopped(netdev_v))
						netif_wake_queue(netdev_v);
#ifdef WDS_FEATURE
					if (mbss_idx < MAX_VMAC_INSTANCE_AP) {
						struct wlprivate *wlpptr_v =
							NETDEV_PRIV(struct
								    wlprivate,
								    netdev_v);
						int wds_idx = 0;

						for (wds_idx = 0;
						     wds_idx < MAX_WDS_PORT;
						     wds_idx++) {
							struct net_device
								*netdev_v_wds =
								wlpptr_v->
								vmacSta_p->
								wdsPort
								[wds_idx].
								netDevWds;

							if (netdev_v_wds &&
							    netif_running
							    (netdev_v_wds) &&
							    netif_queue_stopped
							    (netdev_v_wds))
								netif_wake_queue
									(netdev_v_wds);
						}
					}
#endif
				}
			}
		} else if (netif_queue_stopped(netdev))
			netif_wake_queue(netdev);

	}

	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	WLDBG_EXIT(DBG_LEVEL_13);

}
#else
void
wlTxDone(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//      u_int8_t rate2Rate11AG[] = { 0,1,2,3,0,4,5,6,7,8,9,10,11 };
	//      u_int8_t rate2Rate11B[] = { 0,1,2,3 };
	unsigned long flags;
	int num;
#ifdef ZERO_COPY
	int i;
#endif
	extStaDb_StaInfo_t *pStaInfo;
	WLDBG_ENTER(DBG_LEVEL_13);
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	{
		for (num = 0; num < NUM_OF_DESCRIPTOR_DATA; num++) {
		    /**
		      WAR: this is to workaround the tx Traffic stop problem where both 
		      "pNextTxDesc" and "pStaleTxDesc" point to the same idle descriptor
		      and the rest of MAX_NUM_TX_DESC-1 of descriptors has been 
		      processed by fw and need to be free up by driver.
		      This WAR should be removed when the issue is rootcaused.
		     */
			if ((CURR_TXD(num)) &&
			    (wlpptr->wlpd_p->fwDescCnt[num] >=
			     (MAX_NUM_TX_DESC - 1))
			    && (wlpptr->wlpd_p->descData[num].pNextTxDesc ==
				CURR_TXD(num))) {
				if (CURR_TXD(num)->Status == 0) {
					/*When fwDescCnt==256 and pStaleTxDesc->Status==0, fwDescCnt should be 255.
					 * When all desc Status==1, fwDescCnt is 256. We minus fwDescCnt when this condition occurs.
					 */
					if (wlpptr->wlpd_p->fwDescCnt[num] >=
					    MAX_NUM_TX_DESC)
						wlpptr->wlpd_p->
							fwDescCnt[num]--;

					CURR_TXD(num) = CURR_TXD(num)->pNext;
				}
			}

			while ((CURR_TXD(num))
			       && (CURR_TXD(num)->
				   Status & ENDIAN_SWAP32(EAGLE_TXD_STATUS_OK))
			       &&
			       (!(CURR_TXD(num)->
				  Status &
				  ENDIAN_SWAP32(EAGLE_TXD_STATUS_FW_OWNED)))) {
				if (CURR_TXD(num)->
				    Status & ENDIAN_SWAP32(EAGLE_TXD_STATUS_OK))
				{
				}
#ifdef ZERO_COPY
				if (CURR_TXD(num)->multiframes) {
					for (i = 0;
					     i < CURR_TXD(num)->multiframes;
					     i++) {
						pci_unmap_single(wlpptr->
								 pPciDev,
								 ENDIAN_SWAP32
								 (CURR_TXD
								  (num)->
								  PktPtrArray
								  [i]),
								 CURR_TXD(num)->
								 PktLenArray[i],
								 PCI_DMA_TODEVICE);
						if (CURR_TXD(num)->staInfo &&
						    CURR_TXD(num)->type ==
						    IEEE_TYPE_DATA) {
							pStaInfo =
								(extStaDb_StaInfo_t
								 *)
								CURR_TXD(num)->
								staInfo;
							pStaInfo->RateInfo =
								*(dbRateInfo_t
								  *) &
								(CURR_TXD(num)->
								 RateInfo);

							if (!pStaInfo->RateInfo.
							    Format ||
							    (pStaInfo->RateInfo.
							     Format &&
							     pStaInfo->RateInfo.
							     RateIDMCS == 0))
								pStaInfo->
									aggr11n.
									threshold
									= 0;
							else
								pStaInfo->
									aggr11n.
									threshold
									=
									pStaInfo->
									aggr11n.
									thresholdBackUp;

						}
						if (CURR_TXD(num)->
						    pSkBuffArray[i])
							wl_free_skb(CURR_TXD
								    (num)->
								    pSkBuffArray
								    [i]);
						CURR_TXD(num)->pSkBuffArray[i] =
							NULL;
					}
					CURR_TXD(num)->multiframes = 0;
				} else
#endif
				{
					pci_unmap_single(wlpptr->pPciDev,
							 ENDIAN_SWAP32(CURR_TXD
								       (num)->
								       PktPtr),
							 CURR_TXD(num)->
							 pSkBuff->len,
							 PCI_DMA_TODEVICE);
					if (CURR_TXD(num)->staInfo &&
					    CURR_TXD(num)->type ==
					    IEEE_TYPE_DATA) {
						pStaInfo =
							(extStaDb_StaInfo_t *)
							CURR_TXD(num)->staInfo;
						pStaInfo->RateInfo =
							*(dbRateInfo_t *) &
							(CURR_TXD(num)->
							 RateInfo);
						if (!pStaInfo->RateInfo.Format
						    || (pStaInfo->RateInfo.
							Format &&
							pStaInfo->RateInfo.
							RateIDMCS == 0))
							pStaInfo->aggr11n.
								threshold = 0;
						else
							pStaInfo->aggr11n.
								threshold =
								pStaInfo->
								aggr11n.
								thresholdBackUp;

					}
#ifdef AMSDU_AGGREQ_FOR_8K
					if (CURR_TXD(num)->pSkBuff->truesize >
					    MAX_AGGR_SIZE) {
						//printk("pStaInfo->RateInfo=%x, wcb->rateinfo=%x\n", pStaInfo->RateInfo, CURR_TXD(num)->RateInfo);
						skb_queue_tail(&wlpptr->wlpd_p->
							       aggreQ,
							       CURR_TXD(num)->
							       pSkBuff);
					} else
#endif
						wl_free_skb(CURR_TXD(num)->
							    pSkBuff);
				}
				CURR_TXD(num)->PktLen = 0;
				CURR_TXD(num)->pSkBuff = NULL;
				CURR_TXD(num)->Status =
					ENDIAN_SWAP32(EAGLE_TXD_STATUS_IDLE);
				wlpptr->wlpd_p->fwDescCnt[num]--;
				CURR_TXD(num) = CURR_TXD(num)->pNext;
				wmb();
			}
		}
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	WLDBG_EXIT(DBG_LEVEL_13);
}
#endif
/** private functions **/
#define DES_ADD_OFFSET          6
#define QUEUE_STAOFFSET        ((NUMOFAPS -1) + NUMOFCLIENTS)
#define PROBE_RESPONSE_TXQNUM  ((MAX_STNS + NUMOFAPS + NUMOFCLIENTS) * MAX_TID)
#define MGMT_TXQNUM            ((PROBE_RESPONSE_TXQNUM + 1))

int
wlxmit(struct net_device *netdev, struct sk_buff *skb, UINT8 typeAndBits,
       extStaDb_StaInfo_t * pStaInfo, UINT32 bcast, BOOLEAN eap)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_RSNCONFIG *mib_RSNConfig_p = vmacSta_p->Mib802dot11->RSNConfig;
	u_int16_t *pFwLen;
	unsigned char buffer2[NBR_BYTES_IEEE80211HEADER];
	unsigned int wep_padding = 0, TxPriority = 1, TxDesIndex =
		0, TxQueuePriority = 0;
	unsigned int qos_padding = 0;
	unsigned int data_padding = 0;
	BOOLEAN ucastCipherCCMP = FALSE;
	BOOLEAN mcastCipherCCMP = FALSE;
	IEEEtypes_QoS_Ctl_t QosControl;
	UINT8 *ampduMacAddr = NULL;
	UINT8 type = typeAndBits & 0x3f;
	UINT8 bit7 = typeAndBits & 0x80;
	UINT8 bit6 = typeAndBits & 0x40;
	struct ieee80211_frame *ieee80211_hdr =
		(struct ieee80211_frame *)&skb->data[0];
#ifdef CLIENT_SUPPORT
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
#endif
#ifdef WDS_FEATURE
	struct ieee80211_frame *wh_wds;
	BOOLEAN wds = FALSE;
	struct wds_port *pWdsPort = NULL;
	UINT8 addr4[6];
#endif
	unsigned int AmpduPck = FALSE;
	UINT8 xmitcontrol = 0;
#ifndef NEW_DP
	UINT32 queueindex;
#else
	UINT32 txSendTail;
	UINT32 txSendHeadNew;
	wltxdesc_t *pNextTxDesc;
	unsigned int mic_pedding = 0;
	UINT32 txdesclimit;
#endif
	WLDBG_ENTER(DBG_LEVEL_13);

#ifdef AUTOCHANNEL
	if (vmacSta_p->StopTraffic)
		return EAGAIN;
#endif

#ifdef NEW_DP
	if (type == IEEE_TYPE_DATA)
		txdesclimit = wlpptr->wlpd_p->TxDescLimit - 1024;	//reserve 1k desc for mgmt & ctrl pkt so in heavy traffic, mgmt & ctrl still can tx
	else
		txdesclimit = wlpptr->wlpd_p->TxDescLimit;

	if (wlpptr->wlpd_p->descData[0].txDescBusyCnt >= (txdesclimit - 1)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "Descriptor full");
		if (type == IEEE_TYPE_MANAGEMENT) {
			printk("TX MGMT descriptor full\n");
		}
		return EAGAIN;
	}
	if (type == IEEE_TYPE_DATA) {
		txSendTail = wlpptr->wlpd_p->descData[0].TxSentTail;
		txSendHeadNew = wlpptr->wlpd_p->descData[0].TxSentHead;

		if (((txSendHeadNew + 1) & (MAX_TX_RING_SEND_SIZE - 1)) ==
		    txSendTail) {
			/* Update the txSendTail */
			txSendTail =
				readl(wlpptr->ioBase1 + MACREG_REG_TxSendTail);
			wlpptr->wlpd_p->descData[0].TxSentTail = txSendTail;

			if (((txSendHeadNew + 1) & (MAX_TX_RING_SEND_SIZE -
						    1)) == txSendTail) {
				WLDBG_EXIT_INFO(DBG_LEVEL_13,
						"try again later");
				return EAGAIN;
			}
		}

		goto newdp_data;
	}
#endif

	memcpy(&buffer2[0], &skb->data[0], NBR_BYTES_IEEE80211HEADER);

#ifdef WDS_FEATURE
#ifdef CLIENT_SUPPORT
	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA)
#endif
	{
		pWdsPort = getWdsPortFromNetDev(wlpptr, netdev);

		if (*(wlpptr->vmacSta_p->Mib802dot11->mib_wdsEnable) &&
		    (pWdsPort != NULL)) {
			memcpy(&addr4[0],
			       &skb->data[NBR_BYTES_IEEE80211HEADER + 2], 6);
			wds = TRUE;
		}
#ifdef MULTI_AP_SUPPORT
		//if (pStaInfo && pStaInfo->MultiAP_4addr == 1)
		//{
		//      memcpy(&addr4[0],&skb->data[NBR_BYTES_IEEE80211HEADER + 2],6);    
		//}
#endif
	}
#endif

	if (type == IEEE_TYPE_DATA) {
		/* For QoS data frames pick up the QoS information from the header */
		if (ieee80211_hdr->FrmCtl.Subtype == QoS_DATA)
			*(UINT16 *) & QosControl =
				*(UINT16 *) & skb->
				data[NBR_BYTES_IEEE80211HEADER];
		else
			*(UINT16 *) & QosControl = 0;

		qos_padding = 2;
		if (!eap) {
			if (mib->Privacy->PrivInvoked)
				wep_padding = 4;

			if (mib->Privacy->RSNEnabled /*&& pStaInfo */ ) {
				wep_padding = 8;
				if (bcast) {
					if ((!
					     (mib->RSNConfigWPA2->WPA2Enabled ||
					      mib->RSNConfigWPA2->
					      WPA2OnlyEnabled) &&
					     mib_RSNConfig_p->
					     MulticastCipher[3] == 4) ||
					    ((mib->RSNConfigWPA2->WPA2Enabled ||
					      mib->RSNConfigWPA2->
					      WPA2OnlyEnabled) &&
					     mib->RSNConfigWPA2->
					     MulticastCipher[3] == 4)) {
						mcastCipherCCMP = TRUE;
						data_padding = 0;
					} else {
						data_padding = 4;
					}
				} else {
					/* Unicast cipher CCMP */
					if (pStaInfo) {
						if ((pStaInfo->keyMgmtStateInfo.
						     RsnIEBuf[0] == 48 &&
						     pStaInfo->keyMgmtStateInfo.
						     RsnIEBuf[13] == 4) ||
						    (pStaInfo->keyMgmtStateInfo.
						     RsnIEBuf[0] == 221 &&
						     pStaInfo->keyMgmtStateInfo.
						     RsnIEBuf[17] == 4)) {
							ucastCipherCCMP = TRUE;
							data_padding = 0;
						} else {
							data_padding = 4;
						}
					}
				}
			}
#ifdef MRVL_WAPI
			if ((ieee80211_hdr->FrmCtl.Wep == 1) &&
			    mib->Privacy->WAPIEnabled) {
				wep_padding = 18;	//WAPI PN(16)+keyid(1)+reserve(1)
				data_padding = 16;	//MIC length
			}
#endif
		} else {
			/* Use multicast data rate for eapol pkts */
			xmitcontrol |= EAGLE_TXD_XMITCTRL_USE_MC_RATE;
			TxPriority = 3;
		}

		if (!*(mib->QoSOptImpl)) {
			//Non qos condition, goes to q 0 now
			if (!eap)
				TxPriority = 0;
		} else {
#define SRC_ADD_OFFSET 16
			//the following check handles wmm w2w case 
			/* NBR_BYTES_CTRLSTATUS+NBR_BYTES_DURATION+NBR_BYTES_ADDR1+NBR_BYTES_ADDR2=2+2+6+6=16 */
			extStaDb_StaInfo_t *pStaSrc = NULL;
			if (vmacSta_p->VMacEntry.modeOfService !=
			    VMAC_MODE_CLNT_INFRA)
				pStaSrc =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & (skb->
								   data
								   [SRC_ADD_OFFSET]),
							    STADB_NO_BLOCK);
			if (pStaSrc) {
				TxPriority = 3;
			} else {
				if (!eap) {
					if ((skb->priority) & 0x7)
						TxPriority =
							AccCategoryQ[(skb->
								      priority)
								     & 0x7];
					else
						TxPriority =
							AccCategoryQ[QosControl.
								     tid];
					if (pStaInfo && !pStaInfo->IsStaQSTA)
						TxPriority = 1;
				}
			}
		}
	} else {
		*(UINT16 *) & QosControl = 0;
		if (type == IEEE_TYPE_MANAGEMENT) {
			TxPriority = 3;
#ifdef CONFIG_IEEE80211W
			if (IS_MULTICAST(ieee80211_hdr->addr1))
				bcast = 1;
			else
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) ieee80211_hdr->
							    addr1, 0);
			{
				extern int isRobustMgmtFrame(UINT16 Subtype);
				if (!bcast && pStaInfo &&
				    (pStaInfo->Ieee80211wSta) &&
				    isRobustMgmtFrame(ieee80211_hdr->FrmCtl.
						      Subtype) &&
				    (pStaInfo->ptkCipherOuiType !=
				     CIPHER_OUI_TYPE_NONE)) {
					if (!bit6) {
						ieee80211_hdr->FrmCtl.Wep = 1;
					}
				}
			}
			if (pStaInfo && pStaInfo->Ieee80211wSta &&
			    ieee80211_hdr->FrmCtl.Wep) {
				memcpy(&buffer2[0], &skb->data[0],
				       NBR_BYTES_IEEE80211HEADER);
				wep_padding = 8;
				ucastCipherCCMP = TRUE;
				data_padding = 0;
				if ((pStaInfo->ptkCipherOuiType ==
				     CIPHER_OUI_TYPE_GCMP) ||
				    (pStaInfo->ptkCipherOuiType ==
				     CIPHER_OUI_TYPE_GCMP_256) ||
				    (pStaInfo->ptkCipherOuiType ==
				     CIPHER_OUI_TYPE_CCMP_256))
					mic_pedding = 16;
				else
					mic_pedding = 8;
			} else if (bcast) {
				extern int macMgmtBIP(vmacApInfo_t * vmac_p,
						      macmgmtQ_MgmtMsg2_t *
						      mgtFrm, int payload_len);
				int payload =
					skb->len - sizeof(IEEEtypes_MgmtHdr2_t);
				if ((payload =
				     macMgmtBIP(vmacSta_p,
						(macmgmtQ_MgmtMsg2_t *) & skb->
						data[0], payload)) != 0) {
					printk("%s:\n", vmacSta_p->dev->name);
					//_hexdump("before mgmy BIP", skb->data, skb->len);
					skb_put(skb,
						payload +
						sizeof(IEEEtypes_MgmtHdr2_t) -
						skb->len);
					//_hexdump("mgmt BIP", skb->data, skb->len);
				}
			}
#endif
		} else
			TxPriority = 1;
	}

#if NUM_OF_DESCRIPTOR_DATA >3
#ifdef MCAST_PS_OFFLOAD_SUPPORT
	if (bcast && vmacSta_p->PwrSaveStnCnt) {
		TxDesIndex =
			NUM_EDCA_QUEUES + wlpptr->vmacSta_p->VMacEntry.macId;
	} else
#endif
	{
		TxDesIndex = TxPriority;
	}
#endif

#ifdef NEW_DP
	if (wlpptr->wlpd_p->descData[0].pNextTxDesc == NULL)
#else
	if (wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc == NULL)
#endif
	{
		return EAGAIN;
	} else {
		/*Only queue to tx desc when Status is 0 (not when 0x1 or 0x80000000). If we queue even when Status==0x1
		 * (DMA'd to fw but txdone haven't change Status to 0), mismatch of fwDescCnt with actual number of desc with Status==0 
		 * could happen. E.g fwDescCnt 256 instead of 255 when there is one desc with Status==0. This can cause Tx to stall
		 * when fwDescCnt==256 and pStaleTxDesc->Status==0.
		 */
#ifdef NEW_DP
		txSendTail = wlpptr->wlpd_p->descData[0].TxSentTail;
		txSendHeadNew = wlpptr->wlpd_p->descData[0].TxSentHead;

		if (((txSendHeadNew + 1) & (MAX_TX_RING_SEND_SIZE - 1)) ==
		    txSendTail) {
			/* Update the txSendTail */
			txSendTail =
				readl(wlpptr->ioBase1 + MACREG_REG_TxSendTail);
			wlpptr->wlpd_p->descData[0].TxSentTail = txSendTail;

			if (((txSendHeadNew + 1) & (MAX_TX_RING_SEND_SIZE -
						    1)) == txSendTail) {
				WLDBG_EXIT_INFO(DBG_LEVEL_13,
						"try again later");
				return EAGAIN;
			}
		}
#else
		if (wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->Status !=
		    ENDIAN_SWAP32(EAGLE_TXD_STATUS_IDLE)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_13, "try again later");

			/*interrupt fw anyway */
			if (wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
			    Status & ENDIAN_SWAP32(EAGLE_TXD_STATUS_FW_OWNED))
				writel(MACREG_H2ARIC_BIT_PPA_READY,
				       wlpptr->ioBase1 +
				       MACREG_REG_H2A_INTERRUPT_EVENTS);

			wlpptr->wlpd_p->txDoneCnt = 0;

			return EAGAIN;
		}
#endif
	}

	// Addr4 is included so subtract 6 for headroom and push.
	if (skb_headroom(skb) <
	    NBR_BYTES_ADD_TXFWINFO + wep_padding - qos_padding - 6) {
		//the code should not come here, need to find out why this happens!!!!
		printk("skb_headroom error \n");
		return EAGAIN;
	}
#ifdef MRVL_WAPI
	if ((wep_padding == 18) && (mib->Privacy->WAPIEnabled)) {
		pFwLen = (u_int16_t *) skb_push(skb, wep_padding);
		*pFwLen =
			ENDIAN_SWAP16((skb->len -
				       NBR_BYTES_COMPLETE_TXFWHEADER +
				       data_padding));
	} else
#endif
	{
		pFwLen = (u_int16_t *) skb_push(skb,
						NBR_BYTES_ADD_TXFWINFO +
						wep_padding - qos_padding - 6);
		*pFwLen =
			ENDIAN_SWAP16(skb->len - NBR_BYTES_COMPLETE_TXFWHEADER +
				      mic_pedding + data_padding);
	}

	memcpy(&skb->data[NBR_BYTES_FW_TX_PREPEND_LEN], &buffer2[0],
	       NBR_BYTES_IEEE80211HEADER);
	memset(&skb->data[NBR_BYTES_IEEE80211HEADER + 2], 0, 6 + wep_padding);

	if (type == IEEE_TYPE_DATA) {
		if (!eap) {
			if (!bcast) {
				if (ucastCipherCCMP) {
					InsertCCMPHdr((UINT8 *) & skb->
						      data
						      [NBR_BYTES_IEEE80211HEADER
						       + 2 + 6], 0,
						      pStaInfo->
						      keyMgmtStateInfo.TxIV16,
						      pStaInfo->
						      keyMgmtStateInfo.TxIV32);
					pStaInfo->keyMgmtStateInfo.TxIV16++;
					if (pStaInfo->keyMgmtStateInfo.TxIV16 ==
					    0) {
						pStaInfo->keyMgmtStateInfo.
							TxIV32++;
					}

				}
			} else {
				if (mcastCipherCCMP) {
#ifdef CLIENT_SUPPORT
					if (pStaInfo &&
					    (vmacSta_p->VMacEntry.
					     modeOfService ==
					     VMAC_MODE_CLNT_INFRA)) {
						InsertCCMPHdr((UINT8 *) & skb->
							      data
							      [NBR_BYTES_IEEE80211HEADER
							       + 2 + 6], 0,
							      pStaInfo->
							      keyMgmtStateInfo.
							      TxIV16,
							      pStaInfo->
							      keyMgmtStateInfo.
							      TxIV32);

						pStaInfo->keyMgmtStateInfo.
							TxIV16++;

						if (pStaInfo->keyMgmtStateInfo.
						    TxIV16 == 0) {
							pStaInfo->
								keyMgmtStateInfo.
								TxIV32++;
						}
					} else
#endif
					{
						InsertCCMPHdr((UINT8 *) & skb->
							      data
							      [NBR_BYTES_IEEE80211HEADER
							       + 2 + 6]
							      ,
							      mib->
							      mib_MrvlRSN_GrpKey->
							      g_KeyIndex,
							      vmacSta_p->g_IV16,
							      vmacSta_p->
							      g_IV32);
						vmacSta_p->g_IV16++;
						if (vmacSta_p->g_IV16 == 0) {
							vmacSta_p->g_IV32++;
						}
					}
				}
			}
#ifdef MRVL_WAPI
			if ((wep_padding == 18) && mib->Privacy->WAPIEnabled) {
				UINT32 *pn;
				UINT8 inc;
				if (bcast) {
					pn = (UINT32 *) vmacSta_p->wapiPN_mc;
					inc = 1;
				} else {
					pn = (UINT32 *) vmacSta_p->wapiPN;
					inc = 2;
				}
				INCREASE_WAPI_PN(pn, inc);
				INSERT_WAPIHDR((UINT32 *) & skb->
					       data[NBR_BYTES_IEEE80211HEADER +
						    2 + 6 + 2], pn);
			}
#endif
		}
		if (skb->truesize > MAX_AGGR_SIZE)
			wlpptr->netDevStats.tx_packets += skb->cb[0];
		else
			wlpptr->netDevStats.tx_packets++;
		wlpptr->netDevStats.tx_bytes += skb->len;

		/* add physical interface count for DATA */
		if (wlpptr->master) {
			if (skb->truesize > MAX_AGGR_SIZE)
				((NETDEV_PRIV_P
				  (struct wlprivate,
				   wlpptr->master)))->netDevStats.tx_packets +=
			   skb->cb[0];
			else
				((NETDEV_PRIV_P
				  (struct wlprivate,
				   wlpptr->master)))->netDevStats.tx_packets++;

			((NETDEV_PRIV_P(struct wlprivate, wlpptr->master)))->
				netDevStats.tx_bytes += skb->len;
		}
#ifdef CONFIG_IEEE80211W
	} else {
		if (type == IEEE_TYPE_MANAGEMENT)
			if (ucastCipherCCMP && pStaInfo) {
				InsertCCMPHdr((UINT8 *) & skb->
					      data[NBR_BYTES_IEEE80211HEADER +
						   2 + 6], 0,
					      pStaInfo->keyMgmtStateInfo.TxIV16,
					      pStaInfo->keyMgmtStateInfo.
					      TxIV32);
				pStaInfo->keyMgmtStateInfo.TxIV16++;
				if (pStaInfo->keyMgmtStateInfo.TxIV16 == 0) {
					pStaInfo->keyMgmtStateInfo.TxIV32++;
				}
			}
#endif
	}
#ifdef AMPDU_SUPPORT_TX_CLIENT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		smeGetStaLinkInfo(vmacSta_p->VMacEntry.id,
				  &AssociatedFlag, &bssId[0]);
		ampduMacAddr = &bssId[0];
	} else
#endif
	{
		ampduMacAddr = (UINT8 *) & (skb->data[DES_ADD_OFFSET]);
	}

#ifdef AMPDU_SUPPORT_SBA
	if (type == IEEE_TYPE_DATA) {
#define MAX_TX_QUEUE 8
#ifdef SOC_W8864
#define BA_QUEUE 4
#else
#define BA_QUEUE 5
#endif

		unsigned int i;

		for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM; i++) {
			if ((memcmp
			     ((UINT8 *) & wlpptr->wlpd_p->Ampdu_tx[i].
			      MacAddr[0], ampduMacAddr, 6) == 0)
			    && wlpptr->wlpd_p->Ampdu_tx[i].InUse &&
			    (QosControl.tid ==
			     wlpptr->wlpd_p->Ampdu_tx[i].AccessCat)
			    && wlpptr->wlpd_p->Ampdu_tx[i].AddBaResponseReceive) {
				TxQueuePriority = (BA_QUEUE + i) % MAX_TX_QUEUE;
				AmpduPck = TRUE;
				break;
			}
		}

		if (AmpduPck == FALSE) {
			TxQueuePriority = TxPriority;
		}
	}
#else /* _AMPDU_SUPPORT_SBA */

	if ((memcmp
	     ((UINT8 *) & wlpptr->wlpd_p->Ampdu_tx[0].MacAddr[0], ampduMacAddr,
	      6) == 0)
	    && wlpptr->wlpd_p->Ampdu_tx[0].InUse &&
	    QosControl.tid == wlpptr->wlpd_p->Ampdu_tx[0].AccessCat) {

		TxQueuePriority = 5;
	}

	else if ((memcmp
		  ((UINT8 *) & wlpptr->wlpd_p->Ampdu_tx[1].MacAddr[0],
		   ampduMacAddr, 6) == 0)
		 && wlpptr->wlpd_p->Ampdu_tx[1].InUse &&
		 QosControl.tid == wlpptr->wlpd_p->Ampdu_tx[1].AccessCat) {
		TxQueuePriority = 6;
	}

	else {
		TxQueuePriority = TxPriority;
	}
#endif /* _AMPDU_SUPPORT_SBA */

	//      printk("Value of txpriority = %d QosControl.tid=%d  Ampdu_tx[0].AccessCat =%d inuse = %d\n",TxQueuePriority,QosControl.tid, wlpptr->wlpd_p->Ampdu_tx[0].AccessCat,wlpptr->wlpd_p->Ampdu_tx[0].InUse);
#ifdef WDS_FEATURE
	if (wds) {
		wh_wds = (struct ieee80211_frame *)&skb->
			data[NBR_BYTES_FW_TX_PREPEND_LEN];
		IEEE80211_ADDR_COPY(wh_wds->addr4, addr4);
	}
#endif
#ifdef TCP_ACK_ENHANCEMENT
	/* for TCP ACK Enh */
#ifdef SOC_W8864
	if (TxQueuePriority > 3 && TxQueuePriority < 8)
#else
	if (TxQueuePriority == 5 || TxQueuePriority == 6)
#endif
	{
		if (skb->cb[1] == 1) {
#ifndef NEW_DP
			wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
				tcpack_sn = *((u_int32_t *) & skb->cb[4]);
			wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
				tcpack_src_dst = *((u_int32_t *) & skb->cb[8]);
			TxQueuePriority |= 0x80;
#endif
		}
	}			/* end TCP ACK Enh */
#endif
#ifndef NEW_DP
#ifdef ZERO_COPY
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->multiframes = 0;
#endif
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->TxPriority =
		TxQueuePriority;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->QosCtrl =
		*(UINT16 *) & QosControl;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->pSkBuff = skb;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->PktLen =
		ENDIAN_SWAP16(skb->len);
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->ack_wcb_addr = 0;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->DataRate = 0;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->staInfo =
		(UINT8 *) pStaInfo;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->type = type;
	wmb();
	if (AmpduPck == TRUE) {
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->xmitcontrol = xmitcontrol & 0xfb;	//bit 0: use rateinfo, bit 1: disable ampdu
	} else {
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->xmitcontrol =
			xmitcontrol | 0x4;
	}

	{
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->SapPktInfo =
			ENDIAN_SWAP32(0x00);
	}

	/* QUEUE_STATS: record drv latency and stamp fw start time */
	WLDBG_REC_PKT_DELTA_TIME(skb, PciReadMacReg(netdev, 0x600),
				 wlpptr->wlpd_p->descData[TxDesIndex].
				 pNextTxDesc, TxPriority);

	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->PktPtr =
		ENDIAN_SWAP32(pci_map_single(wlpptr->pPciDev, skb->data,
					     skb->len, PCI_DMA_TODEVICE));
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->Status =
		ENDIAN_SWAP32( /*EAGLE_TXD_STATUS_USED | */
			      EAGLE_TXD_STATUS_FW_OWNED);
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc =
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->pNext;
	/* make sure all the memory transactions done by cpu were completed */
#ifdef __aarch64__
	dmb(sy);		/*Data Memory Barrier */
#else
	dmb();			/*Data Memory Barrier */
#endif
	SET_QUEUE_NUMBER(skb, queueindex);
	if ((skb_queue_len(&wlpptr->wlpd_p->txQ[queueindex]) == 0)) {
		writel(MACREG_H2ARIC_BIT_PPA_READY,
		       wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
	}
#else
/*** new data path ***/
newdp_data:

	pNextTxDesc = &wlpptr->wlpd_p->descData[0].pTxRing[txSendHeadNew];
	TxQueuePriority = 0;	//always use queue 0
	TxDesIndex = 0;
#ifdef TCP_ACK_ENHANCEMENT
	pNextTxDesc->tcp_dst_src = 0;
	pNextTxDesc->tcp_sn = 0;
#endif
	if (type == IEEE_TYPE_MANAGEMENT) {
		extStaDb_StaInfo_t *pStaInfo = NULL;

		struct ieee80211_frame *pWHdr =
			(struct ieee80211_frame *)&skb->data[2];
		ieee80211_hdr = (struct ieee80211_frame *)&skb->data[2];
		pStaInfo =
			extStaDb_GetStaInfo(wlpptr->vmacSta_p, &(pWHdr->addr1),
					    1);

		if (ieee80211_hdr->FrmCtl.Subtype == IEEE_MSG_PROBE_RSP ||
		    ieee80211_hdr->FrmCtl.Subtype == IEEE_MSG_PROBE_RQST) {
			TxQueuePriority = PROBE_RESPONSE_TXQNUM;

		}

		else {
			UINT16 macid = vmacSta_p->VMacEntry.macId;
			if ((macid == NUMOFAPS &&
			     ((ieee80211_hdr->FrmCtl.Wep == 0) ||
			      (ieee80211_hdr->FrmCtl.Wep &&
			       (ieee80211_hdr->FrmCtl.Subtype ==
				IEEE_MSG_AUTHENTICATE))))
			    || (pStaInfo == NULL)
			    || (ieee80211_hdr->FrmCtl.Subtype ==
				IEEE_MSG_ASSOCIATE_RSP)
			    || (ieee80211_hdr->FrmCtl.Subtype ==
				IEEE_MSG_REASSOCIATE_RSP)
			    || (ieee80211_hdr->FrmCtl.Subtype ==
				IEEE_MSG_AUTHENTICATE)) {
				/** assoc is not put sta queue as it might not be setup yet in f/w **/
				TxQueuePriority = MGMT_TXQNUM;
			} else {
				if (bcast && macid != NUMOFAPS) {
					TxQueuePriority = macid * MAX_TID;
				} else if ((ieee80211_hdr->FrmCtl.Subtype ==
					    IEEE_MSG_DEAUTHENTICATE ||
					    ieee80211_hdr->FrmCtl.Subtype ==
					    IEEE_MSG_DISASSOCIATE)) {
					TxQueuePriority =
						MAX_TID * (pStaInfo->StnId +
							   QUEUE_STAOFFSET) + 6;
				} else {
				/** send associated mgmt msg to non-ampdu queue (VO) **/
					if (bit7)
						TxQueuePriority = MGMT_TXQNUM;
					else
						TxQueuePriority =
							MAX_TID *
							(pStaInfo->StnId +
							 QUEUE_STAOFFSET) + 6;
				}
			}
		}
		COPY_MAC_ADDR(pNextTxDesc->u.DA, pWHdr->addr1);
		COPY_MAC_ADDR(pNextTxDesc->u.SA, pWHdr->addr2);
		// Assigning rate code; use legacy 6mbps or 1mbps rate. 
		if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ) {
			// Assigning rate code; use legacy 6mbps rate. 
			pNextTxDesc->u.RateCode =
				RateCode_Type_Legacy +
				(RateCode_Legacy_6MBPS << RateCode_MCS_SHIFT) +
				RateCode_BW_20MHZ;
		} else {
			// Assigning rate code; use legacy 1mbps rate. 
			pNextTxDesc->u.RateCode =
				RateCode_Type_Legacy +
				(RateCode_Legacy_1MBPS_Short <<
				 RateCode_MCS_SHIFT) + RateCode_BW_20MHZ;
		}

		pNextTxDesc->u.MaxRetry = 5; /** this will only affect mgmt packet, should tune later base on subtype **/
		pNextTxDesc->Data =
			ENDIAN_SWAP32(pci_map_single
				      (wlpptr->pPciDev, skb->data,
				       skb->len + mic_pedding,
				       PCI_DMA_TODEVICE));
		pNextTxDesc->Ctrl =
			ENDIAN_SWAP32(((TxQueuePriority & txring_Ctrl_QIDmask)
				       << txring_Ctrl_QIDshift) |
				      (((skb->len + mic_pedding -
					 (sizeof(struct ieee80211_frame)) -
					 2) & txring_Ctrl_LenMask) <<
				       txring_Ctrl_LenShift) |
				      (txring_Ctrl_TAG_MGMT <<
				       txring_Ctrl_TAGshift));
	} else {		//no 802.11 header
		struct ether_header *pEH = (struct ether_header *)skb->data;
		UINT16 macid = vmacSta_p->VMacEntry.macId;
		UINT32 ctrl = 0;

		if (bcast && (macid != NUMOFAPS)) {
			TxQueuePriority = macid * MAX_TID;
#ifdef DOT11V_DMS

			if (*(mib->mib_dms) &&
			    (vmacSta_p->VMacEntry.modeOfService !=
			     VMAC_MODE_CLNT_INFRA)) {
				UINT32 isDmsFlag = FALSE;	//<<<<< Cisco: Replace this flag with the real flag from click data path
				extStaDb_StaInfo_t *pDmsStaInfo = NULL;

#if 0				//for marvell internal unit test only
				UINT8 dms_test_sta1[6] =
					{ 0x02, 0x50, 0x43, 0x22, 0x09, 0xa7 };
				UINT8 dms_test_sta2[6] =
					{ 0x88, 0x32, 0x9b, 0xab, 0x6d, 0x1e };
				UINT8 dms_addr[6] =
					{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

				if (memcmp
				    (&dms_addr[0], &pEH->ether_dhost[0],
				     6) == 0)
					isDmsFlag = TRUE;

				if (isDmsFlag) {
					pDmsStaInfo =
						extStaDb_GetStaInfo(vmacSta_p,
								    &dms_test_sta1,
								    1);
					if (pDmsStaInfo == NULL)
						pDmsStaInfo =
							extStaDb_GetStaInfo
							(vmacSta_p,
							 &dms_test_sta2, 1);

					if (pDmsStaInfo &&
					    (memcmp
					     (pEH->ether_shost,
					      pDmsStaInfo->Addr,
					      sizeof(IEEEtypes_MacAddr_t))))
#else
				if (isDmsFlag) {
					UINT8 dms_test_sta[6] = { 0x02, 0x50, 0x43, 0x22, 0x09, 0xa7 };	//<<<<< Cisco: Remove this line when the sta mac address is ready

					pDmsStaInfo = extStaDb_GetStaInfo(vmacSta_p, &dms_test_sta, 1);	//<<<<< Cisco: Replace the dms_test_sta to be the real mac address from click data path

					if (pDmsStaInfo)
#endif
					{
						IEEEtypes_GenHdr_t *pWHdr;
						UINT16 need_headroom =
							sizeof
							(IEEEtypes_GenHdr_t);
						UINT16 insert_iv =
							0, amsdu_padding = 0;

						/* Transfer to AMSDU 
						   802.11 HDR + PN + AMSDU header + MSDU + padding
						 */
						if (skb->len % 4)
							amsdu_padding =
								4 -
								(skb->len % 4);
						pEH->ether_type = SHORT_SWAP(skb->len - 14 + amsdu_padding);	//fill in length

						if (mib->Privacy->PrivInvoked)	//wep
						{
							insert_iv = 4;
							mic_pedding = 4;
						} else if (mib->Privacy->RSNEnabled)	//tkip/ccmp/gcmp
						{
							insert_iv = 8;

							if (((pDmsStaInfo->
							      keyMgmtStateInfo.
							      RsnIEBuf[0] == 48)
							     && (pDmsStaInfo->
								 keyMgmtStateInfo.
								 RsnIEBuf[13] ==
								 2)) ||
							    ((pDmsStaInfo->
							      keyMgmtStateInfo.
							      RsnIEBuf[0] ==
							      221) &&
							     (pDmsStaInfo->
							      keyMgmtStateInfo.
							      RsnIEBuf[17] ==
							      2)))
								mic_pedding = 12;	//tkip
							else if (((pDmsStaInfo->
								   keyMgmtStateInfo.
								   RsnIEBuf[0]
								   == 48) &&
								  (pDmsStaInfo->
								   keyMgmtStateInfo.
								   RsnIEBuf[13]
								   == 4)) ||
								 ((pDmsStaInfo->
								   keyMgmtStateInfo.
								   RsnIEBuf[0]
								   == 221) &&
								  (pDmsStaInfo->
								   keyMgmtStateInfo.
								   RsnIEBuf[17]
								   == 4)))
								mic_pedding = 8;	//ccmp
							else	//ccmp256/gcmp128/gcmp256
								mic_pedding =
									16;
						}
#ifdef MRVL_WAPI
						else if (mib->Privacy->
							 WAPIEnabled) {
							insert_iv = 18;
							mic_pedding = 16;
						}
#endif
						need_headroom += insert_iv;

						if (skb_headroom(skb) <
						    need_headroom) {
							struct sk_buff *txSkb_p;

							//allocate a new one and free the old one
							txSkb_p =
								skb_realloc_headroom
								(skb,
								 need_headroom);
							wl_free_skb(skb);

							if (txSkb_p = NULL)
								return SUCCESS;	//no space, drop this packet

							skb = txSkb_p;
						}
						printk("DMS packet for client %02x:%02x:%02x:%02x:%02x:%02x\n", pDmsStaInfo->Addr[0], pDmsStaInfo->Addr[1], pDmsStaInfo->Addr[2], pDmsStaInfo->Addr[3], pDmsStaInfo->Addr[4], pDmsStaInfo->Addr[5]);

						skb_push(skb, need_headroom);
						pWHdr = (IEEEtypes_GenHdr_t *)
							skb->data;
						//fill in 802.11 hdr
						memset((void *)pWHdr, 0x00,
						       need_headroom);
						pWHdr->FrmBodyLen =
							skb->len -
							sizeof
							(IEEEtypes_GenHdr_t);
						pWHdr->FrmCtl.Type =
							IEEE_TYPE_DATA;
						pWHdr->FrmCtl.Subtype =
							QoS_DATA;
						pWHdr->DurationId = 0;
						pWHdr->FrmCtl.FromDs = 1;
						if (insert_iv)
							pWHdr->FrmCtl.Wep = 1;

						memcpy(pWHdr->Addr1,
						       pDmsStaInfo->Addr,
						       sizeof
						       (IEEEtypes_MacAddr_t));
						memcpy(pWHdr->Addr2,
						       pDmsStaInfo->Bssid,
						       sizeof
						       (IEEEtypes_MacAddr_t));
						memcpy(pWHdr->Addr3,
						       pEH->ether_shost,
						       sizeof
						       (IEEEtypes_MacAddr_t));

						//fill in Tx descriptor
						COPY_MAC_ADDR(pNextTxDesc->u.DA,
							      pWHdr->Addr1);
						COPY_MAC_ADDR(pNextTxDesc->u.SA,
							      pWHdr->Addr2);

						pNextTxDesc->Data =
							ENDIAN_SWAP32
							(pci_map_single
							 (wlpptr->pPciDev,
							  skb->data,
							  (skb->len +
							   mic_pedding +
							   amsdu_padding),
							  PCI_DMA_TODEVICE));

						TxQueuePriority =
							MAX_TID *
							(pDmsStaInfo->StnId +
							 QUEUE_STAOFFSET) +
							((skb->priority) & 0x7);

						pNextTxDesc->u.MaxRetry = 64;	//same definition as FW MAX_RETRY
						pNextTxDesc->u.RateCode =
							0xFFFF;
						pNextTxDesc->Ctrl =
							ENDIAN_SWAP32(((TxQueuePriority & txring_Ctrl_QIDmask) << txring_Ctrl_QIDshift) | (((skb->len + mic_pedding + amsdu_padding - sizeof(IEEEtypes_GenHdr_t)) & txring_Ctrl_LenMask) << txring_Ctrl_LenShift) | ((txring_Ctrl_TAG_MGMT | txring_Ctrl_TAG_AMSDU) << txring_Ctrl_TAGshift));
						goto dmsAmsduSend;
					} else {
						/* free this buffer because the station is not existed */
						wl_free_skb(skb);
						return SUCCESS;
					}
				}

			}
#endif
		} else {
			if (pStaInfo != NULL) {
				if (!eap)
					TxQueuePriority =
						MAX_TID * (pStaInfo->StnId +
							   QUEUE_STAOFFSET) +
						((skb->priority) & 0x7);
				else {
					if (pStaInfo->IsStaQSTA)
						TxQueuePriority = MAX_TID * (pStaInfo->StnId + QUEUE_STAOFFSET) + 6;	//use AC_VO for EAP pkts
					else
						TxQueuePriority = MAX_TID * (pStaInfo->StnId + QUEUE_STAOFFSET);	//use AC_BE for Non-QoS EAP pkts

					ctrl = txring_Ctrl_TAG_EAP <<
						txring_Ctrl_TAGshift;
				}
			} else {
				TxQueuePriority = 0;
			}
		}

#ifdef TCP_ACK_ENHANCEMENT
		if (skb->cb[1] == 2)	//TCP ack frame, might be drop in fw 
		{
			pNextTxDesc->tcp_dst_src =
				*((u_int32_t *) & skb->cb[8]);
			pNextTxDesc->tcp_sn = *((u_int32_t *) & skb->cb[4]);

			ctrl |= (txring_Ctrl_TAG_TCP_ACK <<
				 txring_Ctrl_TAGshift);

		}
#endif

		COPY_MAC_ADDR(pNextTxDesc->u.DA, pEH->ether_dhost);
		COPY_MAC_ADDR(pNextTxDesc->u.SA, pEH->ether_shost);
		skb_pull(skb, sizeof(struct ether_header));
		pNextTxDesc->Data =
			ENDIAN_SWAP32(pci_map_single
				      (wlpptr->pPciDev, skb->data, skb->len,
				       PCI_DMA_TODEVICE));
		pNextTxDesc->Ctrl =
			ENDIAN_SWAP32(((TxQueuePriority & txring_Ctrl_QIDmask)
				       << txring_Ctrl_QIDshift) | ((skb->
								    len &
								    txring_Ctrl_LenMask)
								   <<
								   txring_Ctrl_LenShift)
				      | ctrl);
	}
#ifdef DOT11V_DMS
dmsAmsduSend:
#endif
#ifdef __aarch64__
	pNextTxDesc->User = wlxmit_set_tx_skb(wlpptr, skb);
#else
	pNextTxDesc->User = (UINT32) skb;
#endif
	//skb_queue_tail(&wlpptr->wlpd_p->txQueRecord, skb);

	if (++txSendHeadNew >= MAX_TX_RING_SEND_SIZE)
		txSendHeadNew = 0;
	wlpptr->wlpd_p->descData[0].TxSentHead = txSendHeadNew;
	wmb();
	writel(txSendHeadNew, wlpptr->ioBase1 + MACREG_REG_TxSendHead);
	wlpptr->wlpd_p->descData[0].txDescBusyCnt++;
#endif
	netdev->trans_start = jiffies;
	wlpptr->wlpd_p->fwDescCnt[TxDesIndex]++;
	WLDBG_EXIT(DBG_LEVEL_13);
	return SUCCESS;
}

#ifdef ZERO_COPY
int
wlxmitmfs(struct net_device *netdev, struct sk_buff *skb[],
	  extStaDb_StaInfo_t * pStaInfo, int nof)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_RSNCONFIG *mib_RSNConfig_p = vmacSta_p->Mib802dot11->RSNConfig;
	int hdrlen;
	int pktlen = skb[0]->len;
	int keyidx = -1;
	u_int16_t *pFwLen;
	unsigned char buffer2[NBR_BYTES_IEEE80211HEADER];
	unsigned int wep_padding = 0, TxPriority = 1, TxDesIndex = 0;
	unsigned int qos_padding = 0;
	unsigned int data_padding = 0;
	BOOLEAN ucastCipherCCMP = FALSE;
	BOOLEAN mcastCipherCCMP = FALSE;
	IEEEtypes_QoS_Ctl_t QosControl;
	int type = IEEE_TYPE_DATA;
	UINT32 bcast = 0;
	BOOLEAN eap = FALSE;
	int i, tmplen = 0;
#ifdef WDS_FEATURE
	struct ieee80211_frame *wh_wds;
	BOOLEAN wds = FALSE;
	struct wds_port *pWdsPort = NULL;
	UINT8 addr4[6];
#endif
	WLDBG_ENTER(DBG_LEVEL_13);
#ifdef AUTOCHANNEL
	{
		if (vmacSta_p->StopTraffic)
			return EAGAIN;
	}
#endif
	memcpy(&buffer2[0], &skb[0]->data[0], NBR_BYTES_IEEE80211HEADER);
	*(UINT16 *) & QosControl =
		*(UINT16 *) & skb[0]->data[NBR_BYTES_IEEE80211HEADER];
#ifdef WDS_FEATURE
	pWdsPort = getWdsPortFromNetDev(wlpptr, netdev);

	if (*(mib->mib_wdsEnable) && (pWdsPort != NULL)) {
		memcpy(&addr4[0], &skb[0]->data[NBR_BYTES_IEEE80211HEADER + 2],
		       6);
		wds = TRUE;
	}
#endif
	if (type == IEEE_TYPE_DATA) {
		qos_padding = 2;
		if (!eap) {
			if (mib->Privacy->PrivInvoked)
				wep_padding = 4;

			if (mib->Privacy->RSNEnabled) {
				wep_padding = 8;
				if (bcast) {
					if ((!
					     (mib->RSNConfigWPA2->WPA2Enabled ||
					      mib->RSNConfigWPA2->
					      WPA2OnlyEnabled) &&
					     mib_RSNConfig_p->
					     MulticastCipher[3] == 4) ||
					    ((mib->RSNConfigWPA2->WPA2Enabled ||
					      mib->RSNConfigWPA2->
					      WPA2OnlyEnabled) &&
					     mib->RSNConfigWPA2->
					     MulticastCipher[3] == 4)) {
						mcastCipherCCMP = TRUE;
						data_padding = 0;
					} else {
						data_padding = 4;
					}
				} else {
					/* Unicast cipher CCMP */
					if ((pStaInfo->keyMgmtStateInfo.
					     RsnIEBuf[0] == 48 &&
					     pStaInfo->keyMgmtStateInfo.
					     RsnIEBuf[13] == 4) ||
					    (pStaInfo->keyMgmtStateInfo.
					     RsnIEBuf[0] == 221 &&
					     pStaInfo->keyMgmtStateInfo.
					     RsnIEBuf[17] == 4)) {
						ucastCipherCCMP = TRUE;
						data_padding = 0;
					} else {
						data_padding = 4;
					}
				}
			}
		}

		if (!*(mib->QoSOptImpl)) {
			//Non qos condition, goes to q 0 now
			TxPriority = 0;
		} else {
#define SRC_ADD_OFFSET 16
			//the following check handles wmm w2w case 
			/* NBR_BYTES_CTRLSTATUS+NBR_BYTES_DURATION+NBR_BYTES_ADDR1+NBR_BYTES_ADDR2=2+2+6+6=16 */
			extStaDb_StaInfo_t *pStaSrc = NULL;
			if (vmacSta_p->VMacEntry.modeOfService !=
			    VMAC_MODE_CLNT_INFRA)
				pStaSrc =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & (skb->
								   data
								   [SRC_ADD_OFFSET]),
							    0);
			if (pStaSrc) {
				TxPriority = 3;
			} else {
				if (!eap) {
					TxPriority =
						AccCategoryQ[QosControl.tid];
					if (pStaInfo && !pStaInfo->IsStaQSTA)
						TxPriority = 1;
				}
			}
		}
	} else {
		TxPriority = 1;
	}
#if NUM_OF_DESCRIPTOR_DATA >3
	TxDesIndex = TxPriority;
#endif
	if (wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
	    SoftStat & SOFT_STAT_STALE) {
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "try again later");
		//interrupt fw anyway
		writel(MACREG_H2ARIC_BIT_PPA_READY,
		       wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);

		return EAGAIN;
	}

	if (skb_headroom(skb[0]) <
	    NBR_BYTES_ADD_TXFWINFO + wep_padding - qos_padding) {
		//the code should not come here, need to find out why this happens!!!!
		return EAGAIN;
	}
	//
	pFwLen = (u_int16_t *) skb_push(skb[0],
					NBR_BYTES_ADD_TXFWINFO + wep_padding -
					qos_padding - 6);
	for (i = 0; i < nof; i++) {
		tmplen += skb[i]->len;
	}
	*pFwLen =
		ENDIAN_SWAP16(tmplen - NBR_BYTES_COMPLETE_TXFWHEADER +
			      wep_padding + data_padding);
	memcpy(&skb[0]->data[NBR_BYTES_FW_TX_PREPEND_LEN], &buffer2[0],
	       NBR_BYTES_IEEE80211HEADER);

	memset(&skb[0]->data[NBR_BYTES_IEEE80211HEADER + 2], 0,
	       6 + wep_padding);
	if (type == IEEE_TYPE_DATA) {
		if (!eap) {
			if (!bcast) {
				if (ucastCipherCCMP) {
					InsertCCMPHdr((UINT8 *) & skb[0]->
						      data
						      [NBR_BYTES_IEEE80211HEADER
						       + 2 + 6], 0,
						      pStaInfo->
						      keyMgmtStateInfo.TxIV16,
						      pStaInfo->
						      keyMgmtStateInfo.TxIV32);
					pStaInfo->keyMgmtStateInfo.TxIV16++;
					if (pStaInfo->keyMgmtStateInfo.TxIV16 ==
					    0) {
						pStaInfo->keyMgmtStateInfo.
							TxIV32++;
					}

				}
			} else {
				if (mcastCipherCCMP) {
					InsertCCMPHdr((UINT8 *) & skb[0]->
						      data
						      [NBR_BYTES_IEEE80211HEADER
						       + 2 + 6]
						      ,
						      mib->mib_MrvlRSN_GrpKey->
						      g_KeyIndex,
						      vmacSta_p->g_IV16,
						      vmacSta_p->g_IV32);
					vmacSta_p->g_IV16++;
					if (vmacSta_p->g_IV16 == 0) {
						vmacSta_p->g_IV32++;
					}
				}
			}
		}
	}
#ifdef WDS_FEATURE
	if (wds) {
		wh_wds = (struct ieee80211_frame *)&skb[0]->
			data[NBR_BYTES_FW_TX_PREPEND_LEN];
		IEEE80211_ADDR_COPY(wh_wds->addr4, addr4);
	}
#endif
#ifndef NEW_DP
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->multiframes =
		ENDIAN_SWAP32(nof);
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->TxPriority =
		TxDesIndex;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->QosCtrl =
		*(UINT16 *) & QosControl;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->pSkBuff = 0;	// skb[0];
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->PktLen =
		ENDIAN_SWAP16(tmplen);
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->ack_wcb_addr = 0;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->DataRate = 0;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->staInfo =
		(UINT8 *) pStaInfo;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->type = type;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->SapPktInfo =
		ENDIAN_SWAP32(0x00);

	for (i = 0; i < nof; i++) {
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
			PktLenArray[i] = ENDIAN_SWAP16(skb[i]->len);
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
			PktPtrArray[i] =
			ENDIAN_SWAP32(pci_map_single
				      (wlpptr->pPciDev, skb[i]->data,
				       skb[i]->len, PCI_DMA_TODEVICE));
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->
			pSkBuffArray[i] = skb[i];

		wlpptr->netDevStats.tx_packets++;
		wlpptr->netDevStats.tx_bytes += skb[i]->len;

	}
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->SoftStat |=
		SOFT_STAT_STALE;
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->Status =
		ENDIAN_SWAP32( /*EAGLE_TXD_STATUS_USED | */
			      EAGLE_TXD_STATUS_FW_OWNED);
	wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc =
		wlpptr->wlpd_p->descData[TxDesIndex].pNextTxDesc->pNext;
	if (skb_queue_len(&wlpptr->wlpd_p->txQ[TxDesIndex]) == 0) {
		writel(MACREG_H2ARIC_BIT_PPA_READY,
		       wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
	}
#endif
	netdev->trans_start = jiffies;
	wlpptr->wlpd_p->fwDescCnt[TxDesIndex]++;
	WLDBG_EXIT(DBG_LEVEL_13);
	return SUCCESS;
}
#endif

int
wlDataTxUnencr(struct sk_buff *skb, struct net_device *netdev,
	       extStaDb_StaInfo_t * pStaInfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned long flags;
	UINT32 bcast = 0;

	WLDBG_ENTER(DBG_LEVEL_13);

	if ((netdev->flags & IFF_RUNNING) == 0) {
		wlpptr->netDevStats.tx_dropped++;
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: itf not running",
				netdev->name);
		return -ENETDOWN;
	}

	if ((skb = ieee80211_encap(skb, netdev, TRUE)) == NULL) {
		goto error;
	}
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);

	if (wlxmit(netdev, skb, IEEE_TYPE_DATA, pStaInfo, bcast, TRUE)) {
		WLDBG_INFO(DBG_LEVEL_13, "could not xmit");
		wlpptr->netDevStats.tx_errors++;
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
		wlTxDone(netdev);
		goto error1;
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
	WLDBG_EXIT(DBG_LEVEL_13);
	return 0;

error:
error1:
	if (skb) {
#ifdef AMSDU_AGGREQ_FOR_8K
		if (skb->truesize > MAX_AGGR_SIZE) {
			skb_queue_tail(&wlpptr->wlpd_p->aggreQ, skb);
		} else
#endif
			wl_free_skb(skb);
	}
	WLDBG_EXIT_INFO(DBG_LEVEL_13, NULL);
	return 0;

}
