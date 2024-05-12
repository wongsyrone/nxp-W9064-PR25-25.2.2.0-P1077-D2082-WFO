/** @file ap8xLnxXmit.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2005-2021 NXP
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
#include <net/tcp.h>

#include "wldebug.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxBQM.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "StaDb.h"
#include "mlmeApi.h"
#include "wds.h"
#include "ccmp.h"
#include "smac_hal_inf.h"
#ifdef MRVL_WAPI
#include "wapi.h"
#endif
#include "trace.h"


#ifdef WLAN_INCLUDE_TSO
#define tso_size gso_size
#endif				/*WLAN_INCLUDE_TSO */

#ifdef EWB
#include "ewb_packet.h"
#endif

#ifdef MULTI_AP_SUPPORT
#include "wlApi.h"
#endif				/* MULTI_AP_SUPPORT */

#ifdef MPRXY
#include "ap8xLnxMPrxy.h"

#define IS_IN_CLASSD(a)         ((((UINT32)(a)) & 0xf0000000) == 0xe0000000)
#define IS_IN_MULTICAST(a)              IS_IN_CLASSD(a)
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP        0x0800	/* IP protocol */
#define ETHERTYPE_IP_NW     0x0008	/* IP protocol network byte order */
#endif
#endif

#define MGMT_TXQNUM_OFFSET		6
#define PROBE_REQ_TXQNUM_OFFSET	7

#define SEND_BY_CMD_PATH 1

/* Send EAPOL via command path */
extern UINT32 wlDataTx_SendFrame(struct net_device *dev, struct sk_buff *skb, extStaDb_StaInfo_t * pStaInfo);

extern wltxdesc_t *wlSkbToCfhDl(struct net_device *netdev, struct sk_buff *skb, wltxdesc_t * txcfg, extStaDb_StaInfo_t * pStaInfo, int qid, int type);

extern unsigned int dbg_invalid_skb;
extern int txq_per_sta_timeout;

/*WiFi pre-cert usage. Caution: Any changes here need to verify with WiFi WMM test cases. todo...*/
UINT32 qosctrl_txQLimit = 1000;
UINT8 qosctrl_mode = 0;		//to store what qos ctrl mode, 0:disable, 1:11n, 2:11ac
UINT32 qosctrl_loopcnt[4] = { 0, 0, 0, 0 };	//BK,BE,VI,VO. To cnt loop iteration per AC
UINT32 qosctrl_loopthres[2][4] = { {30, 30, 0, 40}, {0, 0, 0, 60} };	// 11n BK,BE,VI,VO and 11ac BK,BE,VI,VO qos ctrl loop threshold
UINT32 qosctrl_pktthres[2][4] = { {100, 150, 2000, 200}, {0, 1000, 0, 10} };	// 11n BK,BE,VI,VO and 11ac BK,BE,VI,VO qos pkt threshold

/** local definitions **/
#define SET_QUEUE_NUMBER(skb, pri)      { \
		if ((skb->priority) & 0x7) \
			pri = AccCategoryQ[(skb->priority) & 0x7]; \
		else \
			pri = AccCategoryQ[Qos_GetDSCPPriority(skb->data) & 0x7]; \
} \


#define CURR_TXD(i) wlpptr->wlpd_p->descData[i].pStaleTxDesc
#define IEEE80211_ADDR_COPY(dst, src)    memcpy(dst, src, IEEEtypes_ADDRESS_SIZE)

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

unsigned int max_tx_pending;
unsigned int max_tx_pend_cnt_per_q;
unsigned int max_tx_pend_cnt_per_sta;

/** internal functions **/
// Copy MAC Address from Src to Dst
static inline void COPY_MAC_ADDR(u_int8_t * dst, u_int8_t * src)
{
	(*(u_int16_t *) & dst[0]) = (*(u_int16_t *) & src[0]);
	(*(u_int16_t *) & dst[2]) = (*(u_int16_t *) & src[2]);
	(*(u_int16_t *) & dst[4]) = (*(u_int16_t *) & src[4]);
}

/** public data **/

/** private data **/
/** public functions **/
static inline void _wlDataTx(struct sk_buff *skb, struct net_device *netdev);

static inline void wl_mstamp_get(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	skb_mstamp_get(&skb->skb_mstamp);	//struct skb_mstamp
#else
	struct tcp_sock tp;

	tp.tcp_mstamp = 0;
	tcp_mstamp_refresh(&tp);
	skb->skb_mstamp = tp.tcp_mstamp;	//u64
#endif
}

static inline u32 wl_mstamp_us_delta(const struct sk_buff *t1, const struct sk_buff *t0)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	return skb_mstamp_us_delta(&t1->skb_mstamp, &t0->skb_mstamp);
#else
	return tcp_stamp_us_delta(t1->skb_mstamp, t0->skb_mstamp);
#endif
}

#ifdef WLAN_INCLUDE_TSO

static inline unsigned short ipcksum(unsigned char *ip, int len)
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

static inline int wlan_tso_tx(struct sk_buff *skb, struct net_device *netdev)
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
		if (skb_copy_bits(skb, doffset + offset, nskb->data + doffset, frag_size))
			WLDBG_INFO(DBG_LEVEL_13, "TSO BUG\n");
		skb_put(nskb, doffset + frag_size);
		nskb->ip_summed = CHECKSUM_UNNECESSARY;
		nskb->dev = skb->dev;
		nskb->priority = skb->priority;
		nskb->protocol = skb->protocol;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
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
		iph->check = ipcksum((unsigned char *)iph, (iph->ihl << 2));
		//iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
		th->seq = htonl(seq);
		if (offset + doffset + frag_size < skb->len)
			th->fin = th->psh = 0;
		th->check = 0;
		nskb->csum = csum_partial(nskb->data + (iph->ihl << 2), nskb->len - (iph->ihl << 2), 0);
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr, nskb->len - (iph->ihl << 2), IPPROTO_TCP, nskb->csum);
		skb_push(nskb, 14);
		_wlDataTx(nskb, netdev);
		offset += frag_size;
		seq += frag_size;
		id++;
	}

	wl_free_skb(skb);
	return 0;
}

static inline int tcp_checksum_offload(struct sk_buff *skb, struct net_device *netdev)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + 14);
	struct tcphdr *th = (struct tcphdr *)(skb->data + 14 + (iph->ihl * 4));
	struct udphdr *udph = (struct udphdr *)th;

	if ((iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) && (htons(ETH_P_IP) == skb->protocol)) {
		/* The tcp frames from Ethernet marked by Marvell Ethernet driver as CHECKSUM_NONE
		   because it failed the csum offload check as the size failed the minimum byte count (72) requirement.
		   The same frame was also calculated wrong with the wlan driver tcp_checksum_offload function.
		   This still needs some investigation. */
		if (skb->ip_summed == CHECKSUM_NONE || skb->ip_summed == CHECKSUM_UNNECESSARY)
			return 0;

		skb_pull(skb, 14);
		if (iph->protocol == IPPROTO_TCP) {
			th->check = 0;
			skb->csum = csum_partial(skb->data + (iph->ihl << 2), skb->len - (iph->ihl << 2), 0);
			th->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - (iph->ihl << 2), IPPROTO_TCP, skb->csum);
		} else {
			udph->check = 0;
			skb->csum = csum_partial(skb->data + (iph->ihl << 2), skb->len - (iph->ihl << 2), 0);
			udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
		}
		skb_push(skb, 14);
		return 1;
	}
	return 0;
}

#endif
#ifdef TCP_ACK_ENHANCEMENT

/*
#define WORD_SWAP(X) (((X) & 0xff) << 24) +      \
	(((X) & 0xff00) << 8) +      \
	(((X) & 0xff0000) >> 8) +    \
	(((X) & 0xff000000) >> 24)
*/

int get_tcp_ack_sequence_no(struct sk_buff *skb, u_int32_t * seq)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + 14);
	struct tcphdr *th = (struct tcphdr *)(skb->data + 14 + (iph->ihl * 4));

	if ((iph->protocol == IPPROTO_TCP) && (htons(ETH_P_IP) == skb->protocol)) {
		if ((th->ack == 1) && (htons(iph->tot_len) == (iph->ihl * 4 + th->doff * 4))) {

			if (th->syn || th->fin) {
				//do not mark syn and fin as drop cadidate
				skb->cb[1] = 0;
				return 0;
			}

			{
				*((u_int32_t *) & skb->cb[4]) = WORD_SWAP(th->ack_seq);
				*((u_int32_t *) & skb->cb[8]) = th->source | (th->dest << 16);
				skb->cb[1] = 2;	//"consider" to be drop in fw
				*seq = th->ack_seq;

				return 1;
			}
		}
	}
	skb->cb[1] = 0;
	return 0;
}

int tcp_port_match(struct sk_buff *skb1, struct sk_buff *skb2)
{
	struct iphdr *iph1 = (struct iphdr *)(skb1->data + 14);
	struct tcphdr *th1 = (struct tcphdr *)(skb1->data + 14 + (iph1->ihl * 4));

	struct iphdr *iph2 = (struct iphdr *)(skb2->data + 14);
	struct tcphdr *th2 = (struct tcphdr *)(skb2->data + 14 + (iph2->ihl * 4));

	if ((iph1->saddr == iph2->saddr) && (iph1->daddr == iph2->daddr)) {
		if ((th1->source == th2->source) && (th1->dest == th2->dest)) {
			return 1;
		}
	}

	return 0;
}

#endif

static inline struct sk_buff *wl_chktx_headroom(struct sk_buff *skb, struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	struct sk_buff *newskb = NULL;

	// Make sure:
	//      1. the headroom is enough
	//      2. It's 16 byte alignment after ethernet header

	if (skb_headroom(skb) >= SKB_INFO_SIZE) {
		// Enough headroom => nothing to do
		return skb;
	}

	newskb = wl_alloc_skb(skb->len + ALIGN(ETH_HLEN, 16) + ALIGN(ETH_HLEN, 16));

	// Make sure the sufficient space
	if (skb_headroom(newskb) < SKB_INFO_SIZE) {
		skb_reserve(newskb, SKB_INFO_SIZE - skb_headroom(newskb));
	}
	// Make sure it's 16 byte alignment
	if (!IS_ALIGNED(((long)newskb->data), TXBUF_ALIGN)) {
		skb_reserve(newskb, PTR_ALIGN(newskb->data, TXBUF_ALIGN) - newskb->data);
	}
	// Make sure it's 16 byte alignment AFTER ethernet header
	skb_reserve(newskb, (ALIGN(ETH_HLEN, 16) - ETH_HLEN));

	memcpy(newskb->data, skb->data, skb->len);
	skb_put(newskb, skb->len);
	newskb->dev = skb->dev;
	newskb->protocol = skb->protocol;
	// Record the small head room 
	wlpd_p->except_cnt.sml_hdroom_cnt++;
	return newskb;
}

static inline void ap8x_skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	spin_lock_bh(&list->lock);
	__skb_queue_tail(list, newsk);
	spin_unlock_bh(&list->lock);
}

static inline struct sk_buff *ap8x_skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *result, *skb;

	spin_lock(&list->lock);
	skb = skb_peek(list);
	if (skb) {
		if (!skb->prev || !skb->next) {
			list->qlen--;
			spin_unlock(&list->lock);

			WLDBG_ERROR(DBG_LEVEL_0, "ap8x_skb_dequeue: skb %p not linked. skb_data va %p signature 0x%8x dump skb_data:\n",
				    skb, skb->data, *((u32 *) (skb->data - SKB_INFO_SIZE)));
			if (skb->data && skb->len)
				mwl_hex_dump(skb->data, skb->len);

			return 0;
		}
	}
	result = __skb_dequeue(list);
	spin_unlock(&list->lock);
	return result;
}

extern unsigned int mcpkt_show;
int wlDataTx(struct sk_buff *skb, struct net_device *netdev)
{
	UINT8 Priority;
	UINT32 txqlimit;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef MRVL_DFS
	DfsAp *pdfsApMain = NULL;
#endif
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *wlpptrvmac = NETDEV_PRIV_P(struct wlprivate, netdev);
#if defined(QUEUE_STATS_CNT_HIST) || defined(PING_WAR)
	struct ether_header *pEth;
#endif
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
	struct sk_buff *newskb = NULL;
	struct sk_buff *skb_2_send = NULL;
	trace_wlDataTx(skb);
#ifdef TP_PROFILE
	if (wl_tp_profile_test(1, skb, netdev)) {
		wl_free_skb(skb);
		return 0;
	}
#endif
	if (!skb)
		return 0;

	if (mcpkt_show != 0) {
		printk("pkt[%u]\n", skb->len);
		mwl_hex_dump(skb->data, skb->len);
	}
	// Drop the packets if it's sent to parent
	{
		struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
		if (parent_wlpptr == wlpptr) {
			wl_free_skb(skb);
			return 0;
		}
	}

	// Make sure the head room is enough
	newskb = wl_chktx_headroom(skb, netdev);
	if (newskb != skb) {
		// Replace the skb with the one whose headroom is enough
		wl_free_skb(skb);
		skb = newskb;
	}

	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

	txqlimit = priv->vmacSta_p->txQLimit;
	if (qosctrl_mode)
		txqlimit = qosctrl_txQLimit;

	/* QUEUE_STATS: time stamp the start time of the packet */
	WLDBG_SET_PKT_TIMESTAMP(skb);
#ifdef QUEUE_STATS_CNT_HIST
	pEth = (struct ether_header *)skb->data;
	/* track per sta tx count */
	wldbgRecPerStatxPktStats(pEth->ether_dhost, QS_TYPE_TX_EN_Q_CNT);
#endif
	SET_QUEUE_NUMBER(skb, Priority);
#ifdef MRVL_DFS
	pdfsApMain = wlpptr->wlpd_p->pdfsApMain;
	if (pdfsApMain && pdfsApMain->dropData) {
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.tx_dropped++;
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.tx_carrier_errors++;

		/* QUEUE_STATS:  count packets drop due to DFS */
		WLDBG_INC_DFS_DROP_CNT(Priority);

		wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].drop_dfs++;

		wl_free_skb(skb);
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: DFS", netdev->name);
		return 0;
	}
#endif				//MRVL_DFS
	if ((netdev->flags & IFF_RUNNING) == 0) {
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.tx_dropped++;
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.tx_carrier_errors++;

		/* QUEUE_STATS:  count packets drop due to interface is not running */
		WLDBG_INC_IFF_DROP_CNT(Priority);

		wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].drop_iff++;

		wl_free_skb(skb);
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: itf not running", netdev->name);
		return 0;
	}
	if ((wlpptr->wlpd_p->tx_async == TRUE) && (skb_queue_len(&wlpptr->wlpd_p->txQ[Priority]) > txqlimit)) {
		/* QUEUE_STATS:  count packets drop due to queue full */
		WLDBG_INC_TXQ_DROP_CNT(Priority);

#ifdef QUEUE_STATS_CNT_HIST
		/* track per sta tx count */
		wldbgRecPerStatxPktStats(pEth->ether_dhost, QS_TYPE_TX_Q_DROPE_CNT);
#endif
		wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].drop_qfl++;

		wl_free_skb(skb);
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.tx_dropped++;

		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: qlen > limit", netdev->name);
		return 0;	//Can return since we don't need new incoming pkt flush out pkts stuck in txq. timer_routine will flush out stuck pkts in txq
	} else {
#ifdef MPRXY
		/*Move mcast proxy from _wlDataTx to wlDataTx so we only queue pkts to be sent into txq, not all incoming pkts.
		 * This eliminates unnecessary mcast pkt going into txq and will save txq buffer from being occupied by
		 * these unnecesary pkts which are eventually dropped later.
		 */
		if (*(mib->mib_MCastPrxy) && (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA)) {
			dIPAddr = 0;
			ipheader = (struct iphdr *)((UINT8 *) pEth + sizeof(ether_hdr_t));

			/* Get the pointer to the IGMP header and its data */
			if (ipheader->protocol == IPPROTO_IGMP)
				igmpheader = (struct igmphdr *)((UINT8 *) ipheader + ipheader->ihl * 4);

			/* check if IP packet, locate IP header check if IP address is multicast */
			if ((pEth->ether_type == (UINT16) ETHERTYPE_IP_NW && IS_GROUP((UINT8 *) & (pEth->ether_dhost))
			     && (ipheader->protocol != IPPROTO_IGMP)) ||
			    (pEth->ether_type == (UINT16) ETHERTYPE_IP_NW && IS_GROUP((UINT8 *) & (pEth->ether_dhost))
			     && (ipheader->protocol == IPPROTO_IGMP) && igmpheader->type == IGMP_HOST_MEMBERSHIP_QUERY)) {
				IPv4_p = (IEEEtypes_IPv4_Hdr_t *) ((UINT8 *) pEth + sizeof(ether_hdr_t));

				dIPAddr = WORD_SWAP(*((UINT32 *) IPv4_p->dst_IP_addr));

				//check if the pkt is IPv4 or IPV6
				if (IPv4_p->ver == IPV6_VERSION) {
					IPv6_p = (IEEEtypes_IPv6_Hdr_t *) IPv4_p;
					dIPAddr = WORD_SWAP(*((UINT32 *) IPv6_p->dst_IP_addr));
				}
			} else if (ipheader->protocol == IPPROTO_IGMP &&
				   ((igmpheader->type == IGMP_HOST_MEMBERSHIP_REPORT) ||
				    (igmpheader->type == IGMPV2_HOST_MEMBERSHIP_REPORT) || (igmpheader->type == IGMPV3_HOST_MEMBERSHIP_REPORT))) {
				delskb = TRUE;

				/* IGMP reports are not forwarded to all wireless clients */
				goto schedule;
			}
		}
		/*for mDNS etc, 224.0.0.x local group shall be sent out as is since the group */
		/* would not be created at the first place */
		if (*(mib->mib_MCastPrxy) && IS_IN_MULTICAST(dIPAddr) && !LOCAL_MCAST(WORD_SWAP(dIPAddr))) {
			/* Check if IPM address exists in IPM filter address list */
			/* if the address is present in the list then do not proxy */
			for (i = 0; i < *(mib->mib_IPMFilteredAddressIndex); i++) {
				/* Do not proxy, just schedule for tx */
				if (dIPAddr == *(mib->mib_IPMFilteredAddress[i])) {
					/* QUEUE_STATS:  count packets successfully enqueue to TxQ */
					WLDBG_INC_TX_OK_CNT(skb, Priority);
					wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].tx++;

					skb->dev = netdev;
					if (wlpptr->wlpd_p->tx_async == TRUE) {
						WLDBG_REC_TX_Q_DEPTH(wlpptr->wlpd_p->txQ[Priority].qlen, Priority);
						ap8x_skb_queue_tail(&wlpptr->wlpd_p->txQ[Priority], skb);
					} else {
						skb_2_send = skb;
					}
					schedulepkt = TRUE;
					goto schedule;
				}
			}

			/* check if IP packet, locate IP header, check if IP address is multicast */
			/* determine if IP multicast group address is in IP multicast group tables */
			for (i = 0; i < *(mib->mib_IPMcastGrpCount); i++) {
				if (dIPAddr == mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr) {
					/* store the index of this multicast group */
					IPMcastGrpIndex = i;
					break;
				}
			}

			pEthHdrMcast = (struct ether_header *)skb->data;
			if ((IPMcastGrpIndex != 0xFF) && IPMcastGrpIndex < MAX_IP_MCAST_GRPS) {
				for (i = 0; i < mib->mib_IPMcastGrpTbl[IPMcastGrpIndex]->mib_MAddrCount; i++) {
					/* First look up the the unicast address in the station database */
					/*Compare eth source addr with UCastAddr in list to prevent received multicast pkt from client from being converted to unicast */
					/*Received multicast pkt from client should be sent out in wlan and eth as it is */
					if (((extStaDb_GetStaInfo(vmacSta_p, &(mib->mib_IPMcastGrpTbl[IPMcastGrpIndex]->mib_UCastAddr[i]),
								  STADB_UPDATE_AGINGTIME)) != NULL)
					    &&
					    !(memcmp
					      ((char *)&mib->mib_IPMcastGrpTbl[IPMcastGrpIndex]->mib_UCastAddr[i], (char *)pEthHdrMcast->ether_shost,
					       6) == 0)) {
						/* make a copy of the original skb */
						skbCopy = skb_copy(skb, GFP_ATOMIC);

						if (skbCopy == NULL) {
							delskb = TRUE;
							skbCopyError = TRUE;
							goto schedule;
						}

						/* update the destination address from multicast to unicast */
						pEthHdr = (struct ether_header *)skbCopy->data;
						IEEE80211_ADDR_COPY(&(pEthHdr->ether_dhost),
								    mib->mib_IPMcastGrpTbl[IPMcastGrpIndex]->mib_UCastAddr[i]);

						/* QUEUE_STATS:  count packets successfully enqueue to TxQ */
						WLDBG_INC_TX_OK_CNT(skbCopy, Priority);
						WLDBG_REC_TX_Q_DEPTH(wlpptr->wlpd_p->txQ[Priority].qlen, Priority);

						wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].tx++;

						skbCopy->dev = netdev;
						if (wlpptr->wlpd_p->tx_async == TRUE) {
							ap8x_skb_queue_tail(&wlpptr->wlpd_p->txQ[Priority], skbCopy);
						} else {
							skb_2_send = skbCopy;
						}
						schedulepkt = TRUE;
					}
				}
				delskb = TRUE;
				goto schedule;
			} else {
				delskb = TRUE;
				goto schedule;
			}
		} else
#endif				/* MPRXY */
		{
			/* QUEUE_STATS:  count packets successfully enqueue to TxQ */
			WLDBG_INC_TX_OK_CNT(skb, Priority);
			wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].tx++;

			skb->dev = netdev;
#ifdef TCP_ACK_ENHANCEMENT
			{
				u_int32_t seq = 0;

				get_tcp_ack_sequence_no(skb, &seq);
			}
#endif
#ifdef TP_PROFILE
			if (wl_tp_profile_test(2, skb, netdev)) {
				wl_free_skb(skb);
				return 0;
			}
#endif
			if (wlpptr->wlpd_p->tx_async == TRUE) {
				WLDBG_REC_TX_Q_DEPTH(wlpptr->wlpd_p->txQ[Priority].qlen, Priority);
				ap8x_skb_queue_tail(&wlpptr->wlpd_p->txQ[Priority], skb);
			} else {
				skb_2_send = skb;
			}
			schedulepkt = TRUE;
		}
	}

 schedule:

	if (delskb) {
#ifdef QUEUE_STATS_CNT_HIST
		/* track per sta tx count */
		wldbgRecPerStatxPktStats(pEth->ether_dhost, QS_TYPE_TX_Q_DROPE_CNT);
#endif
		((NETDEV_PRIV_P(struct wlprivate, netdev)))->netDevStats.tx_dropped++;
		/* QUEUE_STATS:  count packets drop due to error
		 * Mcat pkt dropped due to not inside mcast proxy list is not counted because it is not an error.
		 */
		if (skbCopyError)
			WLDBG_INC_TX_ERROR_CNT(AccCategoryQ[(skb->priority) & 0x7]);

		wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[Priority].drop_skb++;
		wl_free_skb(skb);
	}

	/*We don't schedule task for every pkt. Only schedule task when it is not scheduled yet.
	 * timer_routine helps flush out all txq when no new incoming pkt by scheduling task. This also prevent pkts sitting inside txq forever
	 * (wlDataTxHdl may not be able to send all pkts in one interupt)
	 */

	if (wlpptr->wlpd_p->tx_async == TRUE) {
		if (schedulepkt) {
#ifdef USE_TASKLET
			tasklet_schedule(&wlpptr->wlpd_p->txtask);
#else
			schedule_work(&wlpptr->wlpd_p->txtask);
#endif
		}
	} else {
		if (skb_2_send != NULL) {
			struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);

#ifdef WLAN_INCLUDE_TSO
			/* The following code is not needed since this condition is checked for and handled in the kernel and this check should never return TRUE.
			   if(skb_shinfo(skb)->frag_list != NULL)
			   {
			   printk("wlan Warning: skb->frag_list != NULL\n");
			   }
			 */
			if (skb_shinfo(skb_2_send)->tso_size) {
				wlpptr->wlpd_p->privStats.tsoframecount++;
				wlan_tso_tx(skb_2_send, netdev);
			} else {
				tcp_checksum_offload(skb_2_send, netdev);
#else
			{
#endif				/* WLAN_INCLUDE_TSO */
				//_wlDataTx(skb, netdev);
				_wlDataTx(skb_2_send, parent_wlpptr->netDev);
			}
		}
	}
	return 0;
}

static inline void _wlDataTx(struct sk_buff *skb, struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct ether_header *pEth;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	UINT32 bcast = 0;
	BOOLEAN eapolPkt = FALSE;
	UINT8 typeAndBits = IEEE_TYPE_DATA;
	trace__wlDataTx(skb);
#ifdef TP_PROFILE
	if (wl_tp_profile_test(4, skb, skb->dev)) {
		wl_free_skb(skb);
		return;
	}
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
				if (!(mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA)) {
#endif
					if (ewbLanRecv(skb, vmacSta_p->macStaAddr)) {
						goto error1;
					}
#ifdef MULTI_AP_SUPPORT
				}
#endif				/* MULTI_AP_SUPPORT */
			}
		}
#endif
		if (!IS_GROUP((UINT8 *) & (pEth->ether_dhost))) {
#ifndef STADB_IN_CACHE
			int stadb_flag = STADB_UPDATE_AGINGTIME;
#else
			int stadb_flag = STADB_FIND_IN_CACHE | STADB_UPDATE_CACHE | STADB_UPDATE_AGINGTIME | STADB_NO_BLOCK;
#endif				/* STADB_IN_CACHE */
			pStaInfo = extStaDb_GetStaInfo(wlpptr->vmacSta_p, &(pEth->ether_dhost), stadb_flag);
#ifdef MULTI_AP_SUPPORT
			if ((vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) && (pStaInfo == NULL) &&
			    ((mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS) || (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS))) {
				UINT8 bssId[6];
				UINT8 found = 0;
				MultiAP_4Addr_Entry_t *entry;
				extStaDb_StaInfo_t *pStaInfo_multiAP = NULL;

				found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) pEth->ether_dhost, &entry, 0);

				if (found == 1) {
					MACADDR_CPY(bssId, entry->tar);
					pStaInfo_multiAP = extStaDb_GetStaInfo(wlpptr->vmacSta_p, (IEEEtypes_MacAddr_t *) & bssId[0], stadb_flag);
					if (pStaInfo_multiAP == NULL)
						goto error;

					if (pStaInfo_multiAP->MultiAP_4addr)
						pStaInfo = pStaInfo_multiAP;

					if (pStaInfo && (pStaInfo->MultiAP_4addr == 2))
						skb->protocol &= ~WL_WLAN_TYPE_WDS;
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
			eapolPkt = ((pEth->ether_type == IEEE_ETHERTYPE_PAE) || (pEth->ether_type == ETH_P_WAPI)) ? TRUE : FALSE;
#else
			eapolPkt = (pEth->ether_type == IEEE_ETHERTYPE_PAE) ? TRUE : FALSE;
#endif
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				// Added for fixing Centrino connectivity issue, check relevant only in AP mode
				if ((mib->Privacy->RSNEnabled) && (pStaInfo->keyMgmtStateInfo.RSNDataTrafficEnabled == 0) && (eapolPkt == FALSE))
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
			if (!*(wlpptr->vmacSta_p->Mib802dot11->mib_wdsEnable) || ((pStaInfo = updateWds(netdev)) == NULL))
				goto error;
#ifdef CLIENT_SUPPORT
		}
#endif
	}
#endif
#ifdef CLIENT_SUPPORT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) GetParentStaBSSID(vmacSta_p->VMacEntry.phyHwMacIndx),
					       STADB_UPDATE_AGINGTIME);
#ifdef MRVL_WPS_CLIENT
#ifdef MRVL_WAPI
		eapolPkt = ((pEth->ether_type == IEEE_ETHERTYPE_PAE) || (pEth->ether_type == ETH_P_WAPI)) ? TRUE : FALSE;
#else
		eapolPkt = (pEth->ether_type == IEEE_ETHERTYPE_PAE) ? TRUE : FALSE;
#endif
		/* The 2-way WPA Group key exchange eapol packets must be encrypted */
		if (pStaInfo && pStaInfo->keyMgmtStateInfo.RSNDataTrafficEnabled && eapolPkt)
			eapolPkt = FALSE;
#endif				//MRVL_WPS_CLIENT
#ifdef MULTI_AP_SUPPORT
		if ((!*(mib->mib_STAMacCloneEnable)) && (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_STA)) {
			/* bSTA connect to fBSS, MultiAP_4addr = 0 */
			if (pStaInfo && (pStaInfo->MultiAP_4addr == 0)) {
				if (ewbLanRecv(skb, vmacSta_p->macStaAddr))
					goto error1;
			} else {
				UINT8 found = 0;
				MultiAP_4Addr_Entry_t *entry;

				// This fourAddrTable for STA mode is used for restoring the SA of Tx
				// which will be used as a lookup table for dropping packet
				found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) pEth->ether_shost, &entry, 1);
				if (found == 1) {
					MACADDR_CPY(entry->tar, pEth->ether_dhost);
				} else {
					FourAddr_AddHashEntry(&entry, (IEEEtypes_MacAddr_t *) pEth->ether_dhost,
							      (IEEEtypes_MacAddr_t *) pEth->ether_shost);
				}
			}
		}
#endif				/* MULTI_AP_SUPPORT */
	}
#endif

	if (*(mib->enable_arp_for_vo) && (pEth->ether_type == IEEE_ETHERTYPE_ARP))
		typeAndBits |= (1 << 5);

	if ((skb = ieee80211_encap(skb, netdev, eapolPkt, pStaInfo)) == NULL)
		goto error;

#ifdef MULTI_AP_SUPPORT
	if ((mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS) && bcast) {
		UINT32 entries = 0;
		UINT8 *staBuf = NULL;
		UINT8 *listBuf = NULL;
		extStaDb_StaInfo_t *StaInfo_p = NULL;

		entries = extStaDb_entries(vmacSta_p, 0);
		if (entries) {
			staBuf = wl_kzalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
			if (staBuf != NULL) {
				int idx;

				extStaDb_list(vmacSta_p, staBuf, 1);
				listBuf = staBuf;

				for (idx = 0; idx < entries; idx++) {
					struct sk_buff *skbCopy = NULL;

					/* avoid forward bcast frame to source */
					if ((skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) &&
					    !memcmp((UINT8 *) & wlpd_p->mac_addr_sta_ta, listBuf, IEEEtypes_ADDRESS_SIZE))
						continue;

					if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,
									     (IEEEtypes_MacAddr_t *) listBuf, STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
						skbCopy = skb_copy(skb, GFP_ATOMIC);
						if (skbCopy == NULL)
							continue;

						if (StaInfo_p->State == ASSOCIATED) {
							SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
							wlxmit(netdev, skbCopy, typeAndBits, StaInfo_p, 0, FALSE, 0);
							SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
						}
					}
					listBuf += sizeof(STA_INFO);
				}
				wl_kfree(staBuf);
			}
		}
	}
#endif				/* MULTI_AP_SUPPORT */

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);

	if (wlxmit(netdev, skb, typeAndBits, pStaInfo, bcast, eapolPkt, 0)) {
		trace_wlxmit_done_fail(skb);
		WLDBG_INFO(DBG_LEVEL_13, "could not xmit");
		netif_stop_queue(netdev);
		SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
		//only platform A390 and A380 do txdone polling
		if (IS_PLATFORM(A390) || IS_PLATFORM(A380)) {
			tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
		}
		goto error1;
	}
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
	trace_wlxmit_done_ok(skb);
#ifdef TP_PROFILE
	if (wlpd_p->wl_tpprofile.tp_point != 0)
		return;
#endif
	WLDBG_EXIT(DBG_LEVEL_13);
#define TXDONE_THRESHOLD 4	/*64 */

	if (IS_PLATFORM(A390) || IS_PLATFORM(A380)) {
		// Polling mode, simulate the tx-done interrupt
		wlpptr->BQRelId |= pbqm_args->buf_release_msix_mask;
		/*if (wlpptr->wlpd_p->txDoneCnt++ > TXDONE_THRESHOLD) { */
		WLDBG_INFO(DBG_LEVEL_5, "%s(), txDoneCnt = %d\n", __func__, wlpptr->wlpd_p->txDoneCnt);
		tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
		wlpptr->wlpd_p->txDoneCnt = 0;
		/*} */
	}
	return;

 error:
 error1:
	if (skb) {
		/* QUEUE_STATS:  count packets drop due to error */
		WLDBG_INC_TX_ERROR_CNT(AccCategoryQ[(skb->priority) & 0x7]);

		wlpptr->netDevStats.tx_dropped++;
		wlpptr->netDevStats.tx_errors++;

		wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[AccCategoryQ[(skb->priority) & 0x7]].drop_skb++;
		wl_free_skb(skb);
	}

	WLDBG_EXIT_INFO(DBG_LEVEL_13, NULL);
	return;
}

void wlDataTxHdl(struct net_device *netdev)
{
	UINT8 num = NUM_OF_DESCRIPTOR_DATA;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct sk_buff *skb;
	u_int32_t cnt, index;
	u_int32_t i;
	u8 schedule = 0;
	unsigned long time_limit = jiffies + HZ;	// tx handle timeout: 1sec

	WLDBG_ENTER(DBG_LEVEL_13);

	if (dbg_tx_pend_cnt_ctrl) {
		if (unlikely(ap8x_get_free_sys_mem_info() < 20)) {
			max_tx_pending = dbg_max_tx_pending_lo;
			max_tx_pend_cnt_per_q = dbg_max_tx_pend_cnt_per_q_lo;
			max_tx_pend_cnt_per_sta = dbg_max_tx_pend_cnt_per_sta_lo;
		} else {
			max_tx_pending = dbg_max_tx_pending;
			max_tx_pend_cnt_per_q = dbg_max_tx_pend_cnt_per_q;
			max_tx_pend_cnt_per_sta = dbg_max_tx_pend_cnt_per_sta;
		}
	}
	if (wlpptr->wlpd_p->bfwreset)
		return;
	trace_wlDataTxHdl_begin(netdev);

	while (num--) {
		index = num;
		if (qosctrl_mode && num < NUM_OF_DESCRIPTOR_DATA)	// As SC5 only has two TxQ, so this change might not need.
			index = 0;	//Needed in WiFi pre-cert. Only fwDescCnt[0] incremented in wlxmit, no need to check all other num??

		/**  since f/w is slower than host cpu, the while loop below might get stuck,
		   one way to fix this is to interrupt f/w to fetch packet when fwowndescriptor is max **/

		if (IS_PLATFORM(A390) || IS_PLATFORM(A380)) {
			if (wlpptr->wlpd_p->fwDescCnt[index] >= MAX_NUM_TX_DESC) {
				tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
				wlpptr->wlpd_p->txDoneCnt = 0;
			}
		}
#ifdef MCAST_PS_OFFLOAD_SUPPORT
		if (qosctrl_mode && num < NUM_OF_DESCRIPTOR_DATA_QOS_CTRL) {
#else
		if (qosctrl_mode && num < NUM_OF_DESCRIPTOR_DATA) {
#endif
			qosctrl_loopcnt[num]++;
			/*Number of loop to skip tx according to AC */
			if (qosctrl_loopcnt[num] > qosctrl_loopthres[qosctrl_mode - 1][num])
				qosctrl_loopcnt[num] = 0;
			else
				continue;	//skip tx

		}
		cnt = 0;
		while (		/*wlpptr->wlpd_p->fwDescCnt[index] < MAX_NUM_TX_DESC  && */
			      (skb = ap8x_skb_dequeue(&wlpptr->wlpd_p->txQ[num])) != 0) {
			trace_wlDataTxHdl_inloop(skb);
#ifdef TP_PROFILE
			if (wl_tp_profile_test(3, skb, skb->dev)) {
				wl_free_skb(skb);
				continue;
			}
#endif
			if (dbg_tcp_ack_drop_skip && skb->cb[1]) {
				struct sk_buff *skb_tmp;
				BOOLEAN skb_queued = FALSE;

				for (i = 0; i < NUM_OF_TCP_ACK_Q; i++) {
					if (!skb_queue_len(&wlpptr->wlpd_p->tcp_ackQ[i])) {
						__skb_queue_tail(&wlpptr->wlpd_p->tcp_ackQ[i], skb);
						skb_queued = TRUE;
						break;
					}

					skb_tmp = skb_peek(&wlpptr->wlpd_p->tcp_ackQ[i]);

					if ((skb_tmp == NULL) || tcp_port_match(skb, skb_tmp)) {
						__skb_queue_tail(&wlpptr->wlpd_p->tcp_ackQ[i], skb);
						skb_queued = TRUE;
						break;
					}
				}
				if (skb_queued == TRUE)
					continue;
			}
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
#endif				/* WLAN_INCLUDE_TSO */
				_wlDataTx(skb, netdev);

#ifdef MCAST_PS_OFFLOAD_SUPPORT
				if (qosctrl_mode && (num < NUM_OF_DESCRIPTOR_DATA_QOS_CTRL)) {	// As SC5 only has two TxQ, so this check might remove later
#else
				if (qosctrl_mode && num < NUM_OF_DESCRIPTOR_DATA) {
#endif
					cnt++;
					if (cnt >= qosctrl_pktthres[qosctrl_mode - 1][num])
						break;	//stop tx if exceed pkt threshold for a particular AC
				}
			}

			if (unlikely(time_after_eq(jiffies, time_limit))) {
				/* tx handle timeout */
				schedule = 1;
				break;
			}
		}

		if (unlikely(schedule)) {
			/* avoid tx handle too long. schedule next tx and leave the loop */
			tasklet_schedule(&wlpptr->wlpd_p->txtask);
			break;
		}
	}

	if (dbg_tcp_ack_drop_skip && !((wlpptr->wlpd_p->tcp_ack_mod++) % dbg_tcp_ack_drop_skip)) {
		for (i = 0; i < NUM_OF_TCP_ACK_Q; i++) {
			if ((skb = skb_dequeue_tail(&wlpptr->wlpd_p->tcp_ackQ[i])) != 0) {
				_wlDataTx(skb, netdev);
			}
			while ((skb = __skb_dequeue(&wlpptr->wlpd_p->tcp_ackQ[i])) != 0) {
				wlpptr->wlpd_p->privStats.tx_tcp_ack_drop_count++;
				wl_free_skb(skb);
			}
		}
	}
	trace_wlDataTxHdl_end(netdev);
}

int wlMgmtTx(struct sk_buff *skb, struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_13);

	if (!skb)
		return 0;

	/* Bypass this check for interface running when a scan is in progress */
	if (!wlpptr->vmacSta_p->busyScanning) {
		if ((netdev->flags & IFF_RUNNING) == 0) {
			wlpptr->netDevStats.tx_dropped++;
			WLDBG_WARNING(DBG_LEVEL_1, "%s: itf not running", netdev->name);
			return -ENETDOWN;
		}
	}

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
	if (wlxmit(netdev, skb, IEEE_TYPE_MANAGEMENT, NULL, 0, FALSE, 0)) {
		WLDBG_ERROR(DBG_LEVEL_1, "could not xmit");
		wlpptr->netDevStats.tx_errors++;
		SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);

		//txdone poll only for platform A390 and A380
		if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
			tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
		goto error;
	}

	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
	WLDBG_EXIT(DBG_LEVEL_13);
	return 0;

 error:
	wl_free_skb(skb);

	WLDBG_EXIT_INFO(DBG_LEVEL_13, NULL);
	return 0;

}

// Dump the tx skb (send, return) pointer to a debug log (/var/txskb_trace)
void wldump_txskb_info(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct file *filp_core = NULL;
	char file_name[96] = { TXSKB_TRACEINFO_FNAME };
	char dat_buf[128];
	u_int32_t i;

	filp_core = filp_open(file_name, O_RDWR | O_CREAT | O_TRUNC, 0);
	if (IS_ERR(filp_core)) {
		pr_err("Open %s failed: errno %ld\n", file_name, PTR_ERR(filp_core));
		return;
	}
	sprintf(dat_buf, "[id]=[send, return] (%u , %u)\n", wlpd_p->tx_pend_skb_msg_id[tst_send], wlpd_p->tx_pend_skb_msg_id[tst_return]);
	__kernel_write(filp_core, dat_buf, strlen(dat_buf), &filp_core->f_pos);
	for (i = 0; i < MAX_PENDSKBMSG; i++) {
		sprintf(dat_buf, "[%u] %p , %p\n", i, wlpd_p->tx_pend_skb_msg[tst_send][i], wlpd_p->tx_pend_skb_msg[tst_return][i]);
		__kernel_write(filp_core, dat_buf, strlen(dat_buf), &filp_core->f_pos);
	}

	filp_close(filp_core, NULL);
	return;
}

void wlTxDone(struct net_device *netdev)
{
	struct sk_buff *skb;
	bm_pe_hw_t *pe_hw;
	unsigned long flags;
	unsigned long RelQs;
	u8 qid;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	UINT32 txqid;

	local_irq_save(flags);
	RelQs = wlpptr->BQRelId;
	wlpptr->BQRelId = 0;
	local_irq_restore(flags);
	wl_chk_drop_pkt(wlpd_p);
	wlpd_p->drv_stats_val.txq_drv_release_cnt[0]++;
	for_each_set_bit(qid, (unsigned long *)&RelQs, (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num)) {
		struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[qid];


		wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		if (isSQFull(&wlqm->sq) == TRUE) {
			struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
			wlexcept_p->qfull_empty[qid][SC5_SQ]++;
		}
		while (isSQEmpty(&wlqm->sq) == FALSE) {
			pe_hw = wlGetRelBufPe(netdev, qid);
			if (pe_hw == NULL)
				continue;

			wlpd_p->drv_stats_val.txq_drv_release_cnt[1]++;

			//Refill bpid=13 buffer back to BMQ13 directly here.
			if (REL_RX_BPID(pe_hw->bpid) == (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {
				U32 qid = (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1);

				wlpd_p->drv_stats_val.bmq13_refill_cnt++;
				//wlpd_p->drv_stats_val.enq_bmqbuf_cnt[qid - SC5_BMQ_START_INDEX]--;
				wlpd_p->drv_stats_val.xx_buf_free_SQ14[qid - SC5_BMQ_START_INDEX]++;

				wlRxBufFillBMEM_Q13(netdev, pe_hw);
				continue;
			}
			skb = wlPeToSkb(netdev, pe_hw);
#if defined(TXACNT_REC)
			{
				MSDU_RING_INFO_st *p_ring_info = &wlpd_p->acntTxMsduRingBaseAddr_v[wlpd_p->acntTxMsduRing_id];

/*				printk("%s, [%d], ring(%p) ring(skb, dat)=(%p, %p), pe(skb, dat)=(%p, %p)\n", 
					netdev->name, wlpd_p->acntTxMsduRing_id, p_ring_info,
					phys_to_virt(p_ring_info->skbAddr), phys_to_virt(p_ring_info->msduPayloadAddr),
					skb, skb->data);
*/
				if ((phys_to_virt(p_ring_info->skbAddr) != skb) || (phys_to_virt(p_ring_info->msduPayloadAddr) != skb->data)) {
					/*printk("%s, [%d], ring(%p) ring(skb, dat)=(%p, %p), pe(skb, dat)=(%p, %p)\n", 
					   netdev->name, wlpd_p->acntTxMsduRing_id, p_ring_info,
					   phys_to_virt(p_ring_info->skbAddr), phys_to_virt(p_ring_info->msduPayloadAddr),
					   skb, skb->data); */
//                                      printk("=====> No equal\n");
				}

				wlpd_p->acntTxMsduRing_id = (wlpd_p->acntTxMsduRing_id + 1) % SC5_TXQ_SIZE;
			}
#endif				//#if defined(TXACNT_REC)

			if (skb != NULL) {
				if (wlpptr->wlpd_p->fwDescCnt[0]-- <= 0)
					wlpptr->wlpd_p->fwDescCnt[0] = 0;

#if defined(TXACNT_REC)
				if (*((struct sk_buff_head **)skb->cb) == &wlpd_p->pend_skb_trace[PENDSKB_TX]) {
#endif				// defined(TXACNT_REC)
					// Remove the skb from the pend_skb_trace[PENDSKB_TX], 
					if ((skb->next != (struct sk_buff *)&wlpd_p->pend_skb_trace[PENDSKB_TX] && !virt_addr_valid(skb->next)) ||
					    (skb->prev != (struct sk_buff *)&wlpd_p->pend_skb_trace[PENDSKB_TX] && !virt_addr_valid(skb->prev))) {
						wlpd_p->except_cnt.skb_notlinked_cnt++;
						if (unlikely((dbg_invalid_skb & dbg_ivalskb_tx) && (dbg_invalid_skb & dbg_ivalskb_class_2))) {
							if (!virt_addr_valid(skb->data) || !virt_addr_valid(skb->data - SKB_INFO_SIZE)) {
								WLDBG_ERROR(DBG_LEVEL_0,
									    "dbgskb: wlTxDone qid %d: skb %p link error. data %p next %p prev %p\n",
									    qid, skb, skb->data, skb->next, skb->prev);
							} else {
								WLDBG_ERROR(DBG_LEVEL_0,
									    "dbgskb: wlTxDone qid %d: skb %p link error. data %p next %p prev %p signature 0x%8x dump skb_data:\n",
									    qid, skb, skb->data, skb->next, skb->prev,
									    *((u32 *) (skb->data - SKB_INFO_SIZE)));
								if (skb->data && skb->len)
									mwl_hex_dump(skb->data, skb->len);
							}

							dbg_coredump(netdev);
						}
						return;
					}
					spin_lock(&wlpd_p->pend_skb_trace[PENDSKB_TX].lock);
					wlpd_p->tx_pend_skb_msg[tst_return][wlpd_p->tx_pend_skb_msg_id[tst_return]] = skb;
					wlpd_p->tx_pend_skb_msg_id[tst_return] = (wlpd_p->tx_pend_skb_msg_id[tst_return] + 1) % MAX_PENDSKBMSG;
					if ((skb->next == NULL) || (skb->prev == NULL)) {
						printk("[Unexpected skb(next, prev): %p, %p], dump dbgmsg: %s \n", skb->next, skb->prev,
						       TXSKB_TRACEINFO_FNAME);
						wldump_txskb_info(netdev);
					} else {
						__skb_unlink(skb, &wlpd_p->pend_skb_trace[PENDSKB_TX]);
					}
					spin_unlock(&wlpd_p->pend_skb_trace[PENDSKB_TX].lock);
#if defined(TXACNT_REC)
				}
				if (txacnt_idmsg > 0) {
					printk("[TXACNT], %s() will free skb(%p), usrs:%u \n", __func__, skb, atomic_read(&skb->users));
				}
#endif				//#if defined(ACNT_REC)
				txqid = skb->priority;

				WLDBG_DATA(DBG_LEVEL_2, " ======> free_pkt (skb=%p, skb_dat=%p, len=%d)\n", skb, skb->data, skb->len);
#ifdef WLS_FTM_SUPPORT
				{
					extern void wlsFTM_HandleTxDone(struct net_device *netdev, struct sk_buff *skb /*tx_info_t *txInfo */ );
					wlsFTM_HandleTxDone(netdev, skb);
				}
#endif
				wl_free_skb(skb);

				wlpd_p->except_cnt.txq_rel_cnt[txqid]++;

				if (txqid < QUEUE_STAOFFSET) {
					if ((txqid % MAX_TID) >= 6) {
						wlpd_p->except_cnt.tx_mgmt_rel_cnt++;
					} else {
						wlpd_p->except_cnt.tx_bcast_rel_cnt++;
					}
				} else {
					UINT32 stnId;
					stnId = (txqid - QUEUE_STAOFFSET) / MAX_TID;
					wlpd_p->except_cnt.tx_sta_rel_cnt[stnId]++;
				}

				wlpd_p->drv_stats_val.txq_drv_release_cnt[3]++;
				{
					CNT_RANGE res;
					SINT32 tx_pend_cnt;

					wlpd_p->drv_stats_val.txbuf_rel_cnt++;

					tx_pend_cnt = (SINT32) (wlpd_p->drv_stats_val.txq_drv_sent_cnt - wlpd_p->drv_stats_val.txbuf_rel_cnt);

					//If the counter is over the level => print the warning message automatically
					res = wlCheckCnterRange(tx_pend_cnt, &(wlpd_p->drv_stats_val.txpend_lastcnt), BMQ_DIFFMSG_COUNT);
					if (res == CNT_RANGE_UP) {
						WLDBG_WARNING(DBG_LEVEL_0, "tx-pending packets count reachs %d\n", tx_pend_cnt);
					} else if (res == CNT_RANGE_DOWN) {
						WLDBG_WARNING(DBG_LEVEL_0, "tx-pending packets count drops down to %d\n", tx_pend_cnt);
					}
				}
			} else
				wlpd_p->drv_stats_val.txq_drv_release_cnt[2]++;
		}		// end of while loop
		// Update the rd_index at the end
		wlUpdateRdPtr(netdev, qid, SC5_SQ, wlqm->sq.rdinx, false);
	}
}

/** private functions **/

//extern int isRobustMgmtFrame(UINT16 Subtype);
extern unsigned int txqid_msg;
static unsigned int wlGetMgmtPktTxq_Nommdu(struct net_device *netdev, UINT32 bcast)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	unsigned int TxQueuePriority;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {	//AP mode
		if (pStaInfo == NULL) {
			if (bcast)
				TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + PROBE_REQ_TXQNUM_OFFSET;
			else
				TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + MGMT_TXQNUM_OFFSET;
		} else
			TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + MGMT_TXQNUM_OFFSET;	//use BSS queue 6
	} else {		//STA mode
		if (bcast)
			TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + PROBE_REQ_TXQNUM_OFFSET;
		else
			TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + MGMT_TXQNUM_OFFSET;
	}
	return TxQueuePriority;
}

static unsigned int wlGetMgmtPktTxq(struct net_device *netdev, struct sk_buff *mgmt_skb)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct ieee80211_frame *ieee80211_hdr = (struct ieee80211_frame *)(mgmt_skb->data);
	unsigned int TxQueuePriority;
	extStaDb_StaInfo_t *pStaInfo;
	UINT32 bcast = 0;

	if (txqid_msg == 1) {
		printk("addr1: %02x:%02x:%02x:%02x:%02x:%02x\n",
		       ieee80211_hdr->addr1[0], ieee80211_hdr->addr1[1], ieee80211_hdr->addr1[2],
		       ieee80211_hdr->addr1[3], ieee80211_hdr->addr1[4], ieee80211_hdr->addr1[5]);
	}
	if (IS_MULTICAST(ieee80211_hdr->addr1)) {
		bcast = 1;
	} else {
		bcast = 0;
	}
	if (bcast == 0) {
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) ieee80211_hdr->addr1, STADB_DONT_UPDATE_AGINGTIME);
	}
	if (bcast == 1) {
		// packets to broadcast/multicast
		TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + MGMT_TXQNUM_OFFSET;
		if (txqid_msg == 1) {
			printk("==> [bcast], (TxQueuePriority, macId)=(%d, %d)\n", TxQueuePriority, vmacSta_p->VMacEntry.macId);
		}
	} else if ((pStaInfo == NULL) || ((pStaInfo != NULL) && (pStaInfo->StnId == MAX_STNS))) {
		// packets unassociated sta
		TxQueuePriority = vmacSta_p->VMacEntry.macId * MAX_TID + PROBE_REQ_TXQNUM_OFFSET;
		if (txqid_msg == 1) {
			printk("==> [not assoc], (TxQueuePriority, macId)=(%d, %d)\n", TxQueuePriority, vmacSta_p->VMacEntry.macId);
		}
	} else {
		// packets to associated sta
		TxQueuePriority = QUEUE_STAOFFSET + pStaInfo->StnId * MAX_TID + PROBE_REQ_TXQNUM_OFFSET;
		if (txqid_msg == 1) {
			printk("==> [assoc_sta] (TxQueuePriority, StnId)=(%d, %d)\n", TxQueuePriority, pStaInfo->StnId);
		}
	}
	return TxQueuePriority;
}

void show_pkt_txqid_msg(struct ieee80211_frame *ieee80211_hdr, struct sk_buff *skb)
{
	char strMgmtType[16][20] = { "assoc_req", "assoc_resp", "reassoc_req", "reassoc_resp", "probe_req", "probe_resp", "beacon",
		"atim", "disassoc", "auth", "deauth"
	};

	if (ieee80211_hdr->FrmCtl.Subtype < 16)
		printk("pkt_type: %s, qid: %d\n", strMgmtType[ieee80211_hdr->FrmCtl.Subtype], skb->priority);
	return;
}

extern int wlFwSetOfdma_Mode(struct net_device *netdev, UINT8 option, UINT8 ru_mode, UINT32 max_delay, U32 max_sta);

int wlxmit(struct net_device *netdev, struct sk_buff *skb, UINT8 typeAndBits, extStaDb_StaInfo_t * pStaInfo, UINT32 bcast, BOOLEAN eap, UINT8 nullpkt)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	struct wlprivate_data *wlpd_p = parent_wlpptr->wlpd_p;
	struct pkttype_info *wlpkt_typecnt_p = &wlpd_p->tpkt_type_cnt;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	unsigned char buffer2[NBR_BYTES_IEEE80211HEADER];
	wltxdesc_t *cfh_dl;
	wltxdesc_t txcfg;
	int qm_txq_id;
	unsigned int TxDesIndex = 0, TxQueuePriority = 0;
	UINT8 type = typeAndBits & 0x1f;
	//UINT8 bit7 = typeAndBits & 0x80;
#ifdef CONFIG_IEEE80211W
	UINT8 bit6 = typeAndBits & 0x40;
#endif
	UINT8 bit5 = typeAndBits & 0x20;
	struct ieee80211_frame *ieee80211_hdr = (struct ieee80211_frame *)&skb->data[0];
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	int pkt_q_per_sta = 0;

	trace_wlxmit(skb);
#ifdef TP_PROFILE
	if (type == IEEE_TYPE_DATA) {
		if (wl_tp_profile_test(6, skb, netdev)) {
			wl_free_skb(skb);
			return 0;
		}
	}
#endif

	/* debug for invalid skb */
	if (unlikely((dbg_invalid_skb & dbg_ivalskb_tx) && wlpd_p->dbgskb.skb_stop)) {
		wl_free_skb(skb);
		return 0;
	}

	WLDBG_ENTER(DBG_LEVEL_13);

	if (wlpd_p->bfwreset) {
		goto drop;
	}
	/* If EAPOL frame, send by command */
	if (*(vmacSta_p->Mib802dot11->mib_eap_rate_fixed) && (type == IEEE_TYPE_DATA) && pStaInfo && eap) {
		UINT32 ret = FAIL;

		ret = wlDataTx_SendFrame(netdev, skb, pStaInfo);
		if (ret == SUCCESS) {
			wl_free_skb(skb);
			WLDBG_EXIT(DBG_LEVEL_13);
			return ret;
		}
	}

#ifdef AUTOCHANNEL
	if (vmacSta_p->master) {
		if (vmacSta_p->master->StopTraffic)
			return EAGAIN;
	} else if (vmacSta_p->StopTraffic)
		return EAGAIN;
#endif				/* AUTOCHANNEL */

	if (type == IEEE_TYPE_MANAGEMENT) {
		ieee80211_hdr = (struct ieee80211_frame *)&skb->data[0];
		memcpy(&wlpkt_typecnt_p->pkt_fc, ieee80211_hdr, sizeof(IEEEtypes_FrameCtl_t));

		if (IS_MULTICAST(ieee80211_hdr->addr1))
			bcast = 1;
		else
			pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) ieee80211_hdr->addr1, STADB_DONT_UPDATE_AGINGTIME);

#ifdef CONFIG_IEEE80211W
		if (!bcast && pStaInfo && (pStaInfo->Ieee80211wSta) &&
		    isRobustMgmtFrame(ieee80211_hdr->FrmCtl.Subtype) && (pStaInfo->ptkCipherOuiType != CIPHER_OUI_TYPE_NONE)) {
			if (!bit6) {
				ieee80211_hdr->FrmCtl.Wep = 1;
			}
		}

		if ((!pStaInfo || !pStaInfo->Ieee80211wSta || !ieee80211_hdr->FrmCtl.Wep) && bcast) {
			extern int macMgmtBIP(vmacApInfo_t * vmac_p, macmgmtQ_MgmtMsg2_t * mgtFrm, int payload_len);
			int payload = skb->len - sizeof(IEEEtypes_MgmtHdr2_t);
			if ((payload = macMgmtBIP(vmacSta_p, (macmgmtQ_MgmtMsg2_t *) & skb->data[0], payload)) != 0) {
				/* printk("%s:\n", vmacSta_p->dev->name); */
				//_hexdump("before mgmy BIP", skb->data, skb->len);
				skb_put(skb, payload + sizeof(IEEEtypes_MgmtHdr2_t) - skb->len);
				//_hexdump("mgmt BIP", skb->data, skb->len);
			}
		}
#endif				/* CONFIG_IEEE80211W */

		memcpy(&buffer2[0], &skb->data[0], NBR_BYTES_IEEE80211HEADER);
		memcpy(&skb->data[NBR_BYTES_ADDR4], &buffer2[0], NBR_BYTES_IEEE80211HEADER);
		skb_pull(skb, NBR_BYTES_ADDR4);

		if (wlpd_p->mmdu_mgmt_enable == FALSE) {
			TxQueuePriority = wlGetMgmtPktTxq_Nommdu(netdev, bcast);
		} else {
			// Over write the txq for MMDU DATA/MGMT TX support
			TxQueuePriority = wlGetMgmtPktTxq(netdev, skb);
		}

		skb->priority = TxQueuePriority;
		qm_txq_id = pbqm_args->txq_start_index;

		// management frame format: 802.11 header + payload.
		InitCFHDLMgmt(netdev, pbqm_args, &txcfg, skb);

		// HTC field bit 20-29 to be used for 0-(SMAC_BSS_NUM-1) (bss index for broadcast mgmt) or >= SMAC_BSS_NUM (for unicast mgmt) for station index
		txcfg.mpdu_ht_a_ctrl &= ~0x3ff00000;	//clear bit20-29
		if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {	//AP mode
			if (pStaInfo == NULL) {
				txcfg.mpdu_ht_a_ctrl |= (vmacSta_p->VMacEntry.macId << 20);
				if (bcast)
					txcfg.mpdu_ht_a_ctrl |= (1 << 29);	//set bit29 for broadcast mgmt pkts 
			} else {
				if (pStaInfo->State != ASSOCIATED)
					txcfg.mpdu_ht_a_ctrl |= (vmacSta_p->VMacEntry.macId << 20);
				else
					txcfg.mpdu_ht_a_ctrl |= ((pStaInfo->StnId + bss_num) << 20);
			}
		} else {	//STA mode
			if (bcast || !pStaInfo)
				txcfg.mpdu_ht_a_ctrl |= (vmacSta_p->VMacEntry.macId << 20) | (1 << 29);
			else
				txcfg.mpdu_ht_a_ctrl |= ((pStaInfo->StnId + bss_num) << 20);
		}
			if (txqid_msg == 1) {
				show_pkt_txqid_msg(ieee80211_hdr, skb);
			}
			cfh_dl = wlSkbToCfhDl(netdev, skb, &txcfg, pStaInfo, qm_txq_id, IEEE_TYPE_MANAGEMENT);
	} /* if(type == IEEE_TYPE_MANAGEMENT)  */
	else {			// else of TYPE_MANAGEMENT
		//no 802.11 header
		UINT16 macid = vmacSta_p->VMacEntry.macId;

		if (!dbg_stop_tx_pending &&
		    (wlpd_p->drv_stats_val.txq_drv_sent_cnt - wlpd_p->drv_stats_val.txq_drv_release_cnt[3] -
		     (wlpd_p->except_cnt.tx_mgmt_send_cnt - wlpd_p->except_cnt.tx_mgmt_rel_cnt) > max_tx_pending)) {
			extern UINT32 quiet_dbg[10];
			quiet_dbg[0]++;
			wlpd_p->except_cnt.tx_drop_over_max_pending++;
			goto drop;
		}

		if (bcast && (macid != wlpd_p->NumOfAPs - 1 || (macid == wlpd_p->NumOfAPs - 1 && vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP)))
#ifdef CONFIG_MC_BC_RATE
		{
			ether_hdr_t *eh = (ether_hdr_t *) ieee80211_hdr;
			if ((eh->da[0] == 0xFF)
			    && (eh->da[1] == 0xFF)
			    && (eh->da[2] == 0xFF)
			    && (eh->da[3] == 0xFF)
			    && (eh->da[4] == 0xFF)
			    && (eh->da[5] == 0xFF)) {
				//broadcast addr
				if (!bit5)
					TxQueuePriority = macid * MAX_TID + 3;
				else
					TxQueuePriority = macid * MAX_TID + 5;
			} else {
				//multicast addr
				TxQueuePriority = macid * MAX_TID;
			}
		}
#else
			TxQueuePriority = macid * MAX_TID;
#endif
		else {
			if (pStaInfo != NULL) {
				U16 txq_offset;
				if (!eap && !nullpkt) {
					if (!bit5) {
						txq_offset = ((skb->priority) & 0x7);
						// For mmdu function => Change TID from #7 to #6, as 7 is reserved for EAPOL and MGMT
						//if (mmdu_data_enable && (txq_offset == 7))
						if (txq_offset == 7)	//7 is reserved for EAPOL and MGMT 
							txq_offset = 6;
					} else {
						txq_offset = 6;	/* AC_VO */
					}
					TxQueuePriority = (MAX_TID * pStaInfo->StnId) + QUEUE_STAOFFSET + txq_offset;
				} else {
					if (wlpd_p->mmdu_data_enable) {
						// Processing eap/eapol packets
						// For mmdu function => always using TID#7 to send eapol packet
						txq_offset = 7;
						TxQueuePriority = (MAX_TID * pStaInfo->StnId) + QUEUE_STAOFFSET + txq_offset;	//use AC_VO for EAP pkts
					} else {
						if (pStaInfo->IsStaQSTA)
							TxQueuePriority = (MAX_TID * pStaInfo->StnId) + QUEUE_STAOFFSET + 7;	//use priority 7 AC_VO for EAP pkts
						else
							TxQueuePriority = (MAX_TID * pStaInfo->StnId) + QUEUE_STAOFFSET;	//use AC_BE for Non-QoS EAP pkts
					}

					/* TODO. Need special processing for EAPOL */
					/*ctrl = txring_Ctrl_TAG_EAP<<txring_Ctrl_TAGshift; */
				}
			} else {
				TxQueuePriority = macid * MAX_TID;
			}
		}

		skb->priority = TxQueuePriority;
			if (vmacSta_p->master && vmacSta_p->master->dl_ofdma_para.all_connected && !vmacSta_p->master->dl_ofdma_para.started) {
				if ((vmacSta_p->master->dl_ofdma_para.all_connected + vmacSta_p->master->dl_ofdma_para.postpone_time) < jiffies) {
					printk("All STAsconnected at %lu, postponed %lu ticks, current jiffies %lu\n",
					       vmacSta_p->master->dl_ofdma_para.all_connected, vmacSta_p->master->dl_ofdma_para.postpone_time,
					       jiffies);
					wlFwSetOfdma_Mode(vmacSta_p->master->dev, vmacSta_p->master->dl_ofdma_para.option,
							  vmacSta_p->master->dl_ofdma_para.ru_mode, vmacSta_p->master->dl_ofdma_para.max_delay,
							  vmacSta_p->master->dl_ofdma_para.max_sta);
					vmacSta_p->master->dl_ofdma_para.started = jiffies;
				}
			}

			/* Tx packet fairly per STA */
			if (wfa_11ax_pf && pStaInfo && vmacSta_p->master && (txq_per_sta_timeout > 0)) {
				if (vmacSta_p->master->dl_ofdma_para.sta_cnt == vmacSta_p->master->dl_ofdma_para.max_sta) {
					int i;
					int q_state = 0;
					int t_state = 0;
					int q_limit = 4096;
					vmacApInfo_t *vmacSta_master_p = vmacSta_p->master;
					struct sk_buff *skb_head = NULL;
					int sta_bitmask = 0;

					/* check if enquque skb */
					for (i = 0; i < vmacSta_p->master->dl_ofdma_para.max_sta; i++) {
						if (!memcmp(pStaInfo->Addr, vmacSta_master_p->ofdma_mu_sta_addr[i], IEEEtypes_ADDRESS_SIZE)) {
							if (wlpptr->wlpd_p->txq_per_sta[i].qlen > q_limit)
								goto drop;

							wl_mstamp_get(skb);
							skb_queue_tail(&wlpptr->wlpd_p->txq_per_sta[i], skb);
							pkt_q_per_sta = 1;
						}

						skb_head = skb_peek(&wlpptr->wlpd_p->txq_per_sta[i]);
						if (skb_head) {
							if (wl_mstamp_us_delta(skb, skb_head) >= txq_per_sta_timeout)
								t_state |= BIT(i);
						}

						if (wlpptr->wlpd_p->txq_per_sta[i].qlen > 0)
							q_state |= BIT(i);

						sta_bitmask |= BIT(i);
					}

					/* check if dequeue skb and send to cfh */
					if (q_state == sta_bitmask || t_state & sta_bitmask) {
						for (i = 0; i < vmacSta_p->master->dl_ofdma_para.max_sta; i++) {
							if ((skb = skb_dequeue(&wlpptr->wlpd_p->txq_per_sta[i])) != NULL) {
								qm_txq_id = pbqm_args->txq_start_index;
								InitCFHDL(netdev, pbqm_args, &txcfg, skb, (void *)pStaInfo, eap, nullpkt);
								cfh_dl = wlSkbToCfhDl(netdev, skb, &txcfg, pStaInfo, qm_txq_id, IEEE_TYPE_DATA);
							}
						}
						return SUCCESS;
					}

				}
			}

			if (!pkt_q_per_sta) {
				qm_txq_id = pbqm_args->txq_start_index;
				// data frame format: 802.3 header + SNAP + payload
				InitCFHDL(netdev, pbqm_args, &txcfg, skb, (void *)pStaInfo, eap, nullpkt);
				cfh_dl = wlSkbToCfhDl(netdev, skb, &txcfg, pStaInfo, qm_txq_id, IEEE_TYPE_DATA);
			}
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,6,0)
	netif_trans_update(netdev);
#else
	netdev->trans_start = jiffies;
#endif

#ifdef TP_PROFILE
	if ((type == IEEE_TYPE_DATA) && IS_TX_TP(wlpd_p->wl_tpprofile.tp_point)) {
		/* in the DID test, since packet is dropped so no need to increase fwDescCnt */
		WLDBG_EXIT(DBG_LEVEL_13);
		return SUCCESS;
	}
#endif

	wlpptr->wlpd_p->fwDescCnt[TxDesIndex]++;
	WLDBG_EXIT(DBG_LEVEL_13);
	return SUCCESS;

 drop:
	wlpptr->netDevStats.tx_dropped++;
	wlpptr->wlpd_p->drv_stats_val.txq_ac_stats[AccCategoryQ[skb->priority & 0x7]].drop_skb++;
	wl_free_skb(skb);
	return SUCCESS;
}

int wlDataTxUnencr(struct sk_buff *skb, struct net_device *netdev, extStaDb_StaInfo_t * pStaInfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 bcast = 0;

	WLDBG_ENTER(DBG_LEVEL_13);

	if ((netdev->flags & IFF_RUNNING) == 0) {
		wlpptr->netDevStats.tx_dropped++;
		WLDBG_EXIT_INFO(DBG_LEVEL_13, "%s: itf not running", netdev->name);
		return -ENETDOWN;
	}

	if ((skb = ieee80211_encap(skb, netdev, TRUE, NULL)) == NULL) {
		goto error;
	}
	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);

	if (wlxmit(netdev, skb, IEEE_TYPE_DATA, pStaInfo, bcast, TRUE, 0)) {
		WLDBG_INFO(DBG_LEVEL_13, "could not xmit");
		wlpptr->netDevStats.tx_errors++;
		SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);

		//txdone poll only for platform A390 and A380
		if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
			tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
		goto error1;
	}
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
	WLDBG_EXIT(DBG_LEVEL_13);
	return 0;

 error:
 error1:
	if (skb)
		wl_free_skb(skb);

	WLDBG_EXIT_INFO(DBG_LEVEL_13, NULL);
	return 0;

}

UINT32 wlDataTx_SendOMFrame(struct net_device * dev, IEEEtypes_MacAddr_t da, UINT16 StnId, UINT16 RxNSS, UINT16 ChnlWidth)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	IEEEtypes_fullHdr_t *fullHdr_p;
	UINT8 *buf;
	UINT32 len, ret = FAIL;

	buf = (UINT8 *) wl_kzalloc(256, GFP_KERNEL);
	if (buf == NULL) {
		return ret;
	}

	fullHdr_p = (IEEEtypes_fullHdr_t *) buf;
	fullHdr_p->FrmCtl.Type = IEEE_TYPE_DATA;
	fullHdr_p->FrmCtl.Subtype = QoS_NULL_DATA;
	fullHdr_p->FrmCtl.Order = 1;

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		/* AP mode */
		fullHdr_p->FrmCtl.FromDs = 1;
		fullHdr_p->FrmCtl.ToDs = 0;
		memcpy(fullHdr_p->Addr3, vmacSta_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);
	} else {
		/* STA mode */
		fullHdr_p->FrmCtl.FromDs = 0;
		fullHdr_p->FrmCtl.ToDs = 1;
		memcpy(fullHdr_p->Addr3, da, IEEEtypes_ADDRESS_SIZE);
	}

	memcpy(fullHdr_p->Addr1, da, IEEEtypes_ADDRESS_SIZE);
	memcpy(fullHdr_p->Addr2, vmacSta_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);

	len = 30;

	fullHdr_p->qos_htc.htc.he_variant.vht = 1;
	fullHdr_p->qos_htc.htc.he_variant.he = 1;
	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		/* AP mode */
		fullHdr_p->qos_htc.htc.he_variant.a_control = CONTROL_ID_OM | ((RxNSS & 0x07) << 4) | ((ChnlWidth & 0x03) << 7);
	} else {
		/* STA mode */
		fullHdr_p->qos_htc.htc.he_variant.a_control = CONTROL_ID_OM | ((RxNSS & 0x07) << 4) | ((ChnlWidth & 0x03) << 7) | (0x01 << 9);
	}

	ret = wlFwSendFrame(dev, StnId, 1, 0, 0x0F0000C3, len, 0, (UINT8 *) buf, NULL);
	wl_kfree(buf);
	return ret;
}

UINT32 wlDataTx_SendFrame(struct net_device * dev, struct sk_buff * skb, extStaDb_StaInfo_t * pStaInfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	IEEEtypes_MgmtHdr2_t *EAPOL_MsgP;
	EAPOL_KeyMsg_t *tx_eapol_ptr = (EAPOL_KeyMsg_t *) skb->data;
	UINT16 key_info_val, key_info_val_l;
	key_info_t *key_info_l = (key_info_t *) (&key_info_val_l);
	UINT8 *buf, *body, *pos;
	UINT32 len, ret = FAIL;

	memcpy(&key_info_val, &tx_eapol_ptr->k.key_info, sizeof(UINT16));
	key_info_val_l = htons(key_info_val);
	if (key_info_l->key_type == 0) {
		/* This is group key, pass it to FW for encryption */
		return ret;
	}

	buf = (UINT8 *) wl_kmalloc(skb->len + 64, GFP_ATOMIC);
	if (buf == NULL) {
		return ret;
	}
	memset(buf, 0, skb->len + 64);
	EAPOL_MsgP = (IEEEtypes_MgmtHdr2_t *) buf;
	EAPOL_MsgP->FrmCtl.Type = 0x02;
	EAPOL_MsgP->FrmCtl.Subtype = 0x08;
	memcpy(EAPOL_MsgP->DestAddr, tx_eapol_ptr->Ether_Hdr.da, IEEEtypes_ADDRESS_SIZE);
	memcpy(EAPOL_MsgP->SrcAddr, tx_eapol_ptr->Ether_Hdr.sa, IEEEtypes_ADDRESS_SIZE);
	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		/* AP mode */
		EAPOL_MsgP->FrmCtl.FromDs = 1;
		EAPOL_MsgP->FrmCtl.ToDs = 0;
		memcpy(EAPOL_MsgP->BssId, tx_eapol_ptr->Ether_Hdr.sa, IEEEtypes_ADDRESS_SIZE);
	} else {
		/* STA mode */
		EAPOL_MsgP->FrmCtl.FromDs = 0;
		EAPOL_MsgP->FrmCtl.ToDs = 1;
		memcpy(EAPOL_MsgP->BssId, tx_eapol_ptr->Ether_Hdr.da, IEEEtypes_ADDRESS_SIZE);
	}
	EAPOL_MsgP->Duration = 0xFFFF;	//smac to calculate

	body = EAPOL_MsgP->Rsrvd;
	len = sizeof(IEEEtypes_MgmtHdr2_t) - 6;
	body[0] = 0x06;
	pos = body + 2;
	pos[0] = pos[1] = 0xaa;
	pos[2] = 0x03;
	pos[3] = 0;
	pos[4] = 0;
	pos[5] = 0;
	len += 8;

	memcpy(&pos[6], &(tx_eapol_ptr->Ether_Hdr.type), SHORT_SWAP(tx_eapol_ptr->hdr_8021x.pckt_body_len) + 6);
	len += SHORT_SWAP(tx_eapol_ptr->hdr_8021x.pckt_body_len) + 6;
	ret = wlFwSendFrame(dev, pStaInfo->StnId, 1, 0, 0x0f010500 /* fix rate 6Mbps */ , 24, len - 24, (UINT8 *) buf, (UINT8 *) & buf[24]);
	wl_kfree(buf);
	return ret;
}

UINT32 wlDataTx_NDP(struct net_device * netdev, IEEEtypes_MacAddr_t * da, u32 txratectrl)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	IEEEtypes_fullHdr_t *Hdr_p = NULL;
	vmacApInfo_t *vmacAp_p = NULL;
	vmacApInfo_t *vmacAp_master_p = NULL;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	UINT32 retval = FAIL;
	u32 hdrlen = 0;
	u32 txrate = 0;
	u8 tid = 0;
	u32 staid = 0;
	u8 macbcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	u8 bcast = 0;
	UINT8 *buf = (UINT8 *) wl_kzalloc(64, GFP_ATOMIC);

	if (!buf)
		goto ret;

	if (wlpptr->vmacSta_p->master)
		vmacAp_master_p = wlpptr->vmacSta_p->master;
	else
		goto ret;

	vmacAp_p = wlpptr->vmacSta_p;

	if (!memcmp(da, macbcast, 6))
		bcast = 1;

	Hdr_p = (IEEEtypes_fullHdr_t *) buf;
	Hdr_p->FrmCtl.Type = IEEE_TYPE_DATA;

	if (*(vmacAp_master_p->Mib802dot11->QoSOptImpl)) {
		/* wmm enabled */
		Hdr_p->FrmCtl.Subtype = QoS_NULL_DATA;
		Hdr_p->qos = 0x6;	//AC_VO
		hdrlen = 26;
		tid = 0x6;
	} else {
		/* wmm disabled */
		Hdr_p->FrmCtl.Subtype = NULL_DATA;
		hdrlen = 24;
		tid = 0;
	}

	memcpy(Hdr_p->Addr1, da, IEEEtypes_ADDRESS_SIZE);
	memcpy(Hdr_p->Addr2, vmacAp_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);

	if (wlpptr->vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {	// AP to STA
		memcpy(Hdr_p->Addr3, vmacAp_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);
		Hdr_p->FrmCtl.FromDs = 1;
		Hdr_p->FrmCtl.ToDs = 0;
		if (!bcast) {
			pStaInfo = extStaDb_GetStaInfo(vmacAp_p, da, STADB_DONT_UPDATE_AGINGTIME);
			if (!pStaInfo) {
				staid = 0;
			} else {
				staid = pStaInfo->StnId;
			}
		} else
			staid = 0xffff;
	} else {
		memcpy(Hdr_p->Addr3, da, IEEEtypes_ADDRESS_SIZE);
		Hdr_p->FrmCtl.FromDs = 0;
		Hdr_p->FrmCtl.ToDs = 1;
	}

	if (!txratectrl) {
		if (*(vmacAp_master_p->Mib802dot11->mib_ApMode) & AP_MODE_A_ONLY) {
			if (wlpptr->devid == SCBT) {
				txrate = 0x0f013400;	//5G  9064 4x4
			} else {
				txrate = 0xff017400;
			}	//5G  9068 8x8
		} else
			txrate = 0x0f013000;	//2G
	}

	if (wlFwSendFrame(netdev, staid, 1, tid, txrate, hdrlen, 0, (UINT8 *) buf, NULL) != SUCCESS) {
		WLDBG_ERROR(DBG_LEVEL_13, "sent a test NDP from %pM to  %pM fail!\n", &vmacAp_p->macStaAddr, da);
		goto ret;
	}

	retval = SUCCESS;

 ret:
	if (buf)
		wl_kfree(buf);

	return retval;
}
