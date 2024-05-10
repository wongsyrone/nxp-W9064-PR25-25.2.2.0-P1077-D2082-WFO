/** @file ewb_packet.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2000-2020 NXP
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/random.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 44))
#include <linux/tqueue.h>
#else
#include <linux/workqueue.h>
#endif
#include <linux/kmod.h>
#include <asm/string.h>
#include <asm/uaccess.h>
#include <asm/irq.h>
#include "linux/udp.h"
#include <linux/skbuff.h>

#include "ewb_packet.h"
#include "ewb_hash.h"
#include "wltypes.h"
#include "ewb_hash.h"
#include "wldebug.h"

#define SKB_IPHDR(skb) ((struct iphdr*)skb->network_header)
#define SKB_NHDR(skb) skb->network_header
#define SKB_MACHDR(skb) skb->mac_header

/* Global Variables */
/* Import Variables */
#define BOOTP_REQUEST   1
#define BOOTP_REPLY     2

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNAK         6
#define DHCPRELEASE     7
#define DHCPINFORM      8
static const UINT8 ic_bootp_cookie[4] = { 99, 130, 83, 99 };

struct bootp_pkt {		/* BOOTP packet format */
	struct iphdr iph;	/* IP header */
	struct udphdr udph;	/* UDP header */
	UINT8 op;		/* 1=request, 2=reply */
	UINT8 htype;		/* HW address type */
	UINT8 hlen;		/* HW address length */
	UINT8 hops;		/* Used only by gateways */
	UINT32 xid;		/* Transaction ID */
	UINT16 secs;		/* Seconds since we started */
	UINT16 flags;		/* Just what it says */
	UINT32 client_ip;	/* Client's IP address if known */
	UINT32 your_ip;		/* Assigned IP address */
	UINT32 server_ip;	/* (Next, e.g. NFS) Server's IP address */
	UINT32 relay_ip;	/* IP address of BOOTP relay */
	UINT8 hw_addr[16];	/* Client's HW address */
	UINT8 serv_name[64];	/* Server host name */
	UINT8 boot_file[128];	/* Name of boot file */
	UINT8 exten[312];	/* DHCP options / BOOTP vendor extensions */
};

void
printMAC(unsigned char *mac)
{
	printk("%x %x %x %x %x %x ", mac[0], mac[1], mac[2], mac[3], mac[4],
	       mac[5]);
}

static void *
ewb_net_hdr(struct sk_buff *skb,
	    unsigned short *pEthType, unsigned short *pNetOffset)
{
	eth_hdr_t *eth = (eth_hdr_t *) skb->data;
	void *post_eth = (void *)(eth + 1);
	unsigned short etherType = ntohs(eth->type);
	unsigned short netOffset = (char *)post_eth - (char *)eth;

	if (etherType == ETH_8021Q_TYPE &&
	    (netOffset + sizeof(vlan8021q_hdr_t)) <= skb_headlen(skb)) {
		// OPTIONAL: Make ^^ a loop for multi VLAN (Q-in-Q)
		// see skb_network_protocol().
		vlan8021q_hdr_t *vlanhdr = (vlan8021q_hdr_t *) post_eth;
		etherType = ntohs(vlanhdr->encapsulated_proto);
		post_eth = (void *)(vlanhdr + 1);
		netOffset = (char *)post_eth - (char *)eth;
	}

	if (pEthType) {
		*pEthType = etherType;
	}
	if (pNetOffset) {
		*pNetOffset = netOffset;
	}

	return post_eth;
}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
int
ewbIpToDs(unsigned char *packet, void *post_eth, unsigned char *rfAddr)
{
	eth_hdr_t *eth;
	ewb_ip_hdr *ip;
	UINT32 srcAddr;

	if (packet == NULL) {
		return (-1);
	}
	eth = (eth_hdr_t *) packet;
	ip = (ewb_ip_hdr *) post_eth;

	memcpy(&srcAddr, ip->srcAddr, 4);
	wetUpdateHashEntry(srcAddr, eth->src);

	/* The original IP may have roamed! */
	memcpy(eth->src, rfAddr, HW_ADDR_LEN);
	return 0;
}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
int
ewbIpFromDs(unsigned char *packet, void *post_eth)
{
	eth_hdr_t *eth;
	ewb_ip_hdr *ip;
	unsigned char *clntMac;
	UINT32 destAddr, srcAddr;

	eth = (eth_hdr_t *) packet;
	ip = (ewb_ip_hdr *) post_eth;

	memcpy(&srcAddr, ip->srcAddr, 4);
	wetClearHashEntry(srcAddr);	/* The original IP may have roamed! */

	memcpy(&destAddr, ip->destAddr, 4);
	if ((clntMac = wetGetHashEntryValue(destAddr)) == NULL) {
		return (-1);
	}
	memcpy(eth->dest, clntMac, HW_ADDR_LEN);
	return 0;
}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
int
ewbArpToDs(unsigned char *packet, void *post_eth, unsigned char *rfAddr)
{
	eth_hdr_t *eth;
	arp_eth_ip_addr *arpAddr;
	UINT32 sndIpAddr;

	if (packet == NULL) {
		return -1;
	}
	eth = (eth_hdr_t *) packet;
	arpAddr = (arp_eth_ip_addr *) (post_eth + ARP_HDR_LEN);
	memcpy(&sndIpAddr, arpAddr->sndIpAddr, 4);

	//printk("\nSend IP %x mac:: ",sndIpAddr);
	//printMAC(eth->src);

	wetUpdateHashEntry(sndIpAddr, eth->src);

	/* The original IP may have roamed! */
	memcpy(eth->src, rfAddr, HW_ADDR_LEN);
	memcpy(arpAddr->sndHwAddr, rfAddr, HW_ADDR_LEN);
	return 0;
}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
int
ewbArpFromDs(unsigned char *packet, void *post_eth)
{
	eth_hdr_t *eth;
	arp_eth_ip_addr *arpAddr;
	unsigned char *clntMac;
	UINT32 sndIpAddr, trgtIpAddr;

	eth = (eth_hdr_t *) packet;
	arpAddr = (arp_eth_ip_addr *) (post_eth + ARP_HDR_LEN);
	memcpy(&sndIpAddr, arpAddr->sndIpAddr, 4);

	wetClearHashEntry(sndIpAddr);	/* The original IP may have roamed! */

	memcpy(&trgtIpAddr, arpAddr->trgtIpAddr, 4);

	//printk("ewbArpFromDs: %x %x ",sndIpAddr,trgtIpAddr);

	if ((clntMac = wetGetHashEntryValue(trgtIpAddr)) == NULL) {
		WLDBG_INFO(DBG_LEVEL_5, "\nCould not find entry for ip:%pIS\n",
			   &trgtIpAddr);
		return -1;
	}
	memcpy(eth->dest, clntMac, HW_ADDR_LEN);
	memcpy(arpAddr->trgtHwAddr, clntMac, HW_ADDR_LEN);
	return 0;
}

int
ewbDhcpFromDs(unsigned char *packet, struct udphdr *udphp)
{
	eth_hdr_t *eth = (eth_hdr_t *) packet;
	char *clntMac;

	clntMac = (char *)udphp + 28;	/* client MAC address */

	//L2: Modify dest mac in MAC header
	memcpy(eth->dest, clntMac, HW_ADDR_LEN);

	return 0;

}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern int
ewbWlanRecv(struct sk_buff *skb, unsigned char *rfAddr)
{
	struct eth_hdr_t *eth;
	unsigned short etherType;
	struct iphdr *iphp;
	struct udphdr *udphp;
	void *post_eth;

	eth = (eth_hdr_t *) skb->data;

	if (IS_BROADCAST_HWADDR(eth->dest))
		return 0;

	/* MULTI_CAST_SUPPORT */
	/* Check to if it's MultiCast */
	if (eth->dest[0] == 0x01)
		return 0;

	post_eth = ewb_net_hdr(skb, &etherType, NULL);
	//printk("\nP WL R %x %x  ",etherType,skb->protocol);

	switch (etherType) {
	case ETH_IP_TYPE:
		iphp = (struct iphdr *)post_eth;
		udphp = (struct udphdr *)(iphp + 1);
		if (!(memcmp(eth->dest, rfAddr, HW_ADDR_LEN))
		    && iphp->protocol == IPPROTO_UDP &&
		    udphp->source == htons(67) && (udphp->dest == htons(67) ||
						   udphp->dest == htons(68))) {
			if (ewbDhcpFromDs(skb->data, udphp) < 0)
				return -1;
		} else {
			if (ewbIpFromDs(skb->data, post_eth) < 0)
				return -1;
		}
		break;

	case ETH_ARP_TYPE:
		if (ewbArpFromDs(skb->data, post_eth) < 0)
			return -1;
		break;

	default:
		return 0;
	}

	return 0;
}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern int
ewbLanRecv(struct sk_buff *skb, unsigned char *rfAddr)
{
	eth_hdr_t *eth;
	unsigned short etherType;
	struct iphdr *iphp;
	struct udphdr *udphp;
	struct bootp_pkt *bootp;
	void *post_eth;
	unsigned short net_offset;

	eth = (eth_hdr_t *) skb->data;
	post_eth = ewb_net_hdr(skb, &etherType, &net_offset);

	switch (etherType) {
	case ETH_IP_TYPE:
		iphp = (struct iphdr *)post_eth;
		udphp = (struct udphdr *)(iphp + 1);
		bootp = (struct bootp_pkt *)post_eth;
		if (iphp->protocol == IPPROTO_UDP && bootp->op == BOOTP_REQUEST
		    && (bootp->exten[0] == ic_bootp_cookie[0])
		    && (bootp->exten[1] == ic_bootp_cookie[1])
		    && (bootp->exten[2] == ic_bootp_cookie[2])
		    && (bootp->exten[3] == ic_bootp_cookie[3])
			) {
			if (bootp->exten[6] == DHCPDISCOVER ||
			    bootp->exten[6] == DHCPREQUEST) {
				bootp->flags = 0x0080;
				skb_pull(skb, net_offset);
				udphp->check = 0;
				skb->csum = skb_checksum(skb, iphp->ihl * 4,
							 skb->len -
							 iphp->ihl * 4, 0);
				udphp->check =
					csum_tcpudp_magic(iphp->saddr,
							  iphp->daddr,
							  skb->len -
							  iphp->ihl * 4,
							  IPPROTO_UDP,
							  skb->csum);
				skb_push(skb, net_offset);
			}
		}
		if (ewbIpToDs(skb->data, post_eth, rfAddr) < 0) {
			goto dropPacket;
		}
		break;

	case ETH_ARP_TYPE:
		if (ewbArpToDs(skb->data, post_eth, rfAddr) < 0) {
			goto dropPacket;
		}
		break;

	case EAPOL_TYPE:
		{
			goto sendToWLAN;
		}
	default:
		/* MULTI_CAST_SUPPORT */
		/* Check if MultiCast */
		if (eth->dest[0] == 0x01) {
			memcpy(eth->src, rfAddr, HW_ADDR_LEN);
			goto sendToWLAN;
		}

		goto dropPacket;
	}

sendToWLAN:
	return 0;

dropPacket:
	//panic("Fatal Error! Fix me");
	return (-1);
}

/*************************************************************************
 * Function:
 *
 * Description:
 *
 * Input:
 *
 * Output:
 *
 **************************************************************************/
extern int
ewbInit(void)
{
	wetHashInit();
	return 0;
}
