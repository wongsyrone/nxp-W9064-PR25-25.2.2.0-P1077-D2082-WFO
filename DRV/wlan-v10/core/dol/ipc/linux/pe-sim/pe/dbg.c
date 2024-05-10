/** @file dbg.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#include "radio.h"
#include "dbg.h"

#ifndef LINUX_PE_SIM
#define IPPROTO_ICMP      1
#define IPPROTO_UDP       17
#endif

struct arphdr {
	unsigned short ar_hrd;	/* format of hardware address    */
	unsigned short ar_pro;	/* format of protocol address    */
	unsigned char ar_hln;	/* length of hardware address    */
	unsigned char ar_pln;	/* length of protocol address    */
	unsigned short ar_op;	/* ARP opcode (command)          */
};

struct iphdr {
	unsigned char ihl:4;
	unsigned char version:4;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
	/*The options start here. */
};

struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	union {
		struct {
			unsigned short id;
			unsigned short sequence;
		} echo;
		unsigned int gateway;
		struct {
			unsigned short unused;
			unsigned short mtu;
		} frag;
	} un;
};

struct udphdr {
	unsigned short source;
	unsigned short dest;
	unsigned short len;
	unsigned short check;
};

void
dbg_dump_radio_status(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	int qid;

	if (radio->initialized) {
		printf("== radio rid %d enable %d ==\n", radio->rid,
		       radio->enable);

		/* dump rx descriptor data */
		wlqm = &radio->desc_data[radio->rx_q_data];
		printf("\t rx data \t desc_data[%d] ", radio->rx_q_data);
		printf("\t wlqm->sq.wrinx %d \t rdinx %d \t qsize %d\n",
		       wlqm->sq.wrinx, wlqm->sq.rdinx, wlqm->sq.qsize);

		for (qid = radio->tx_q_start;
		     qid < radio->tx_q_start + radio->tx_q_num; qid++) {
			wlqm = &radio->desc_data[qid];
			printf("\t tx_q_start \t desc_data[%d]", qid);
			printf("\t wlqm->rq.wrinx %d \t rdinx %d \t qsize %d\n",
			       wlqm->rq.wrinx, wlqm->rq.rdinx, wlqm->rq.qsize);
		}

		for (qid = radio->rel_q_start;
		     qid < radio->rel_q_start + radio->rel_q_num; qid++) {
			wlqm = &radio->desc_data[qid];
			printf("\t rel_q_start \t desc_data[%d] ", qid);
			printf("\t wlqm->sq.wrinx %d \t rdinx %d \t qsize %d\n",
			       wlqm->sq.wrinx, wlqm->sq.rdinx, wlqm->sq.qsize);
		}

		for (qid = radio->bm_q_start;
		     qid < radio->bm_q_start + radio->bm_q_num; qid++) {
			wlqm = &radio->desc_data[qid];
			printf("\t bm_q_start \t desc_data[%d] ", qid);
			printf("\t wlqm->rq.wrinx %d \t rdinx %d \t qsize %d\n",
			       wlqm->rq.wrinx, wlqm->rq.rdinx, wlqm->rq.qsize);
		}

		printf("\t pkt_hdr_free_list.cnt %d\n",
		       radio->pkt_ctrl.pkt_hdr_free_list.cnt);
		printf("\t pkt_data_free_list \t");
		for (qid = 0; qid < 4; qid++)
			printf(" [%d].cnt %d ", qid,
			       radio->pkt_ctrl.pkt_data_free_list[qid].cnt);
		printf("\n");
		printf("\t pkt_from_host_list.cnt %d\n",
		       radio->pkt_ctrl.pkt_from_host_list.cnt);
		printf("\t pkt_from_eth_list \t");
		for (qid = 0; qid < 4; qid++)
			printf(" [%d].cnt %d ", qid,
			       radio->pkt_ctrl.pkt_from_eth_list[qid].cnt);
		printf("\n");
	}
}

void
dbg_dump_vif_status(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct vif *vif_info;
	int i;

	if (radio->initialized) {
		printf("== radio rid %d enable %d ==\n", radio->rid,
		       radio->enable);

		for (i = 0; i < radio->bss_num; i++) {
			vif_info = &radio->vif_info[i];
			printf("\tVIF: %d, valid: %d, enable: %d, iso_grp_id: %d, bssid: %pM\n", i, vif_info->valid, vif_info->enable, vif_info->isolate_group_id, vif_info->bssid);
		}
	}
}

bool
dbg_is_arp(const void *packet, bool llc_snap, unsigned short *arp_op)
{
	const unsigned char *data = packet;
	unsigned short protocol;
	struct arphdr *arph;

	/* mac802.3 packet */
	data += (2 * ETH_ALEN);
	if (llc_snap) {
		data += LLC_HDR_LEN;
		protocol = *((unsigned int *)(data - 2)) >> 16;
	} else
		protocol = *((unsigned short *)data);

	if (protocol == BE16_TO_CPU(ETH_P_ARP)) {
		data += sizeof(unsigned short);
		arph = (struct arphdr *)data;
		*arp_op = BE16_TO_CPU(arph->ar_op);
		return true;
	}

	return false;
}

bool
dbg_is_icmp_echo(const void *packet, bool llc_snap, unsigned char *type)
{
	const unsigned char *data = packet;
	unsigned short protocol;
	unsigned char iph_len;
	struct iphdr *iph;
	struct icmphdr *icmph;

	/* mac802.3 packet */
	data += (2 * ETH_ALEN);
	if (llc_snap) {
		data += LLC_HDR_LEN;
		protocol = *((unsigned int *)(data - 2)) >> 16;
	} else
		protocol = *((unsigned short *)data);

	if (protocol == BE16_TO_CPU(ETH_P_IP)) {
		data += sizeof(unsigned short);
		iph = (struct iphdr *)data;
		if (iph->protocol == IPPROTO_ICMP) {
			iph_len = (*data & 0x0F);
			data += (iph_len * 4);
			icmph = (struct icmphdr *)data;
			*type = icmph->type;
			return true;
		}
	}

	return false;
}

bool
dbg_is_dhcp(const void *packet, bool llc_snap, unsigned char *op,
	    unsigned char *dhcp_client)
{
	const unsigned char *data = packet;
	unsigned short protocol;
	unsigned char iph_len;
	struct iphdr *iph;
	struct udphdr *udph;

	/* mac802.3 packet */
	data += (2 * ETH_ALEN);
	if (llc_snap) {
		data += LLC_HDR_LEN;
		protocol = *((unsigned int *)(data - 2)) >> 16;
	} else
		protocol = *((unsigned short *)data);

	if (protocol == BE16_TO_CPU(ETH_P_IP)) {
		data += sizeof(unsigned short);
		iph = (struct iphdr *)data;
		if (iph->protocol == IPPROTO_UDP) {
			iph_len = (*data & 0x0F);
			data += (iph_len * 4);
			udph = (struct udphdr *)data;
			if (((udph->source == BE16_TO_CPU(68)) &&
			     (udph->dest == BE16_TO_CPU(67))) ||
			    ((udph->source == BE16_TO_CPU(67)) &&
			     (udph->dest == BE16_TO_CPU(68)))) {
				data += sizeof(struct udphdr);
				*op = *data;
				memcpy(dhcp_client, data + 28, ETH_ALEN);
				return true;
			}
		}
	}

	return false;
}

void
dbg_dump_arp(const void *packet, bool llc_snap, int len)
{
	const unsigned char *data = packet;
	unsigned short protocol;
	struct arphdr *arph;

	/* mac802.3 packet */
	data += (2 * ETH_ALEN);
	if (llc_snap) {
		data += LLC_HDR_LEN;
		protocol = *((unsigned int *)(data - 2)) >> 16;
	} else
		protocol = *((unsigned short *)data);

	if (protocol == BE16_TO_CPU(ETH_P_ARP)) {
		data += sizeof(unsigned short);
		arph = (struct arphdr *)data;
		if (arph->ar_op == BE16_TO_CPU(ARPOP_REQUEST)) {
			hex_dump("ARP REQUEST: ", (unsigned char *)packet, len);
		} else if (arph->ar_op == BE16_TO_CPU(ARPOP_REPLY)) {
			hex_dump("ARP REPLY: ", (unsigned char *)packet, len);
		}
	}
}

void
dbg_dump_icmp_echo(const void *packet, bool llc_snap, int len)
{
	const unsigned char *data = packet;
	unsigned short protocol;
	unsigned char iph_len;
	struct iphdr *iph;
	struct icmphdr *icmph;

	/* mac802.3 packet */
	data += (2 * ETH_ALEN);
	if (llc_snap) {
		data += LLC_HDR_LEN;
		protocol = *((unsigned int *)(data - 2)) >> 16;
	} else
		protocol = *((unsigned short *)data);

	if (protocol == BE16_TO_CPU(ETH_P_IP)) {
		data += sizeof(unsigned short);
		iph = (struct iphdr *)data;
		if (iph->protocol == IPPROTO_ICMP) {
			iph_len = (*data & 0x0F);
			data += (iph_len * 4);
			icmph = (struct icmphdr *)data;
			if (icmph->type == ICMP_ECHO) {
				hex_dump("ECHO REQUEST: ",
					 (unsigned char *)packet, len);
			} else if (icmph->type == ICMP_ECHOREPLY) {
				hex_dump("ECHO REPLY: ",
					 (unsigned char *)packet, len);
			}
		}
	}
}

void
dbg_dump_dhcp(const void *packet, bool llc_snap, int len)
{
	const unsigned char *data = packet;
	unsigned short protocol;
	unsigned char iph_len;
	struct iphdr *iph;
	struct udphdr *udph;
	const char *dhcp_op[8] = {
		"DHCPDISCOVER",
		"DHCPOFFER",
		"DHCPREQUEST",
		"DHCPDECLINE",
		"DHCPACK",
		"DHCPNAK",
		"DHCPRELEASE",
		"DHCPINFORM"
	};

	/* mac802.3 packet */
	data += (2 * ETH_ALEN);
	if (llc_snap) {
		data += LLC_HDR_LEN;
		protocol = *((unsigned int *)(data - 2)) >> 16;
	} else
		protocol = *((unsigned short *)data);

	if (protocol == BE16_TO_CPU(ETH_P_IP)) {
		data += sizeof(unsigned short);
		iph = (struct iphdr *)data;
		if (iph->protocol == IPPROTO_UDP) {
			iph_len = (*data & 0x0F);
			data += (iph_len * 4);
			udph = (struct udphdr *)data;
			if (((udph->source == BE16_TO_CPU(68)) &&
			     (udph->dest == BE16_TO_CPU(67))) ||
			    ((udph->source == BE16_TO_CPU(67)) &&
			     (udph->dest == BE16_TO_CPU(68)))) {
				data += sizeof(struct udphdr);
				hex_dump(dhcp_op[*data - 1],
					 (unsigned char *)packet, len);
			}
		}
	}
}
