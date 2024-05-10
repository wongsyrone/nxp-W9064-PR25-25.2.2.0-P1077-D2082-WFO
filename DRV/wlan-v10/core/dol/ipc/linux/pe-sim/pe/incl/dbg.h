/** @file dbg.h
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

#ifndef __DBG_H__
#define __DBG_H__

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST     1	/* ARP request  */
#define	ARPOP_REPLY       2	/* ARP reply    */

/* ICMP type */
#define ICMP_ECHOREPLY    0	/* Echo Reply   */
#define ICMP_ECHO         8	/* Echo Request */

void dbg_dump_radio_status(int rid);

void dbg_dump_vif_status(int rid);

bool dbg_is_arp(const void *packet, bool llc_snap, unsigned short *arp_op);

bool dbg_is_icmp_echo(const void *packet, bool llc_snap, unsigned char *type);

bool dbg_is_dhcp(const void *packet, bool llc_snap, unsigned char *op,
		 unsigned char *dhcp_client);

void dbg_dump_arp(const void *packet, bool llc_snap, int len);

void dbg_dump_icmp_echo(const void *packet, bool llc_snap, int len);

void dbg_dump_dhcp(const void *packet, bool llc_snap, int len);

#endif /* __DBG_H__ */
