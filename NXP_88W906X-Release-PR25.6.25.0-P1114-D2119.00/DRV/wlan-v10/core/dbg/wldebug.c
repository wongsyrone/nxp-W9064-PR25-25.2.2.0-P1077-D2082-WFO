/** @file wldebug.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2021 NXP
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
#include "wldebug.h"
#include "ap8xLnxIntf.h"
#include "mib.h"
#include "wl_mib.h"
#include <stdarg.h>
#include "macmgmtap.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxXmit.h"
#include <linux/notifier.h>
#ifdef SOC_W906X
#include "ap8xLnxMonitor.h"
#endif

#include "ap8xLnxBQM.h"


#ifdef AP_MAC_LINUX
#define myprint printk(KERN_INFO
#define myfree   wl_kfree
#define mymalloc(x) wl_kmalloc(x,GFP_KERNEL)
#define STRING_TERMINATOR 0
#else
#define myprint (
#define STRING_TERMINATOR 0x0d
#endif

#define DMEM_IN_FW_START_ADDR 0x20000000

/* default settings */

/** external functions **/

/** external data **/
UINT32 debugmap = 0;

/** internal functions **/
/** public data **/
#ifdef QUEUE_STATS
wldbgPktStats_t wldbgTxACxPktStats[4];
#ifdef QUEUE_STATS_CNT_HIST
wldbgStaTxPktStats_t txPktStats_sta[QS_NUM_STA_SUPPORTED];
wldbgStaRxPktStats_t rxPktStats_sta[QS_NUM_STA_SUPPORTED];
#endif
UINT32 dbgUdpSrcVal = 64;
u_int32_t dbgUdpSrcVal1 = 64;
UINT8 qs_rxMacAddrSave[24];
int numOfRxSta = 0;
#endif
unsigned long debug_m1_delay = 6;	/* 6 ms */

/** public functions **/
int DebugBitSet(UINT8 bit)
{
	return (debugmap & (1 << bit));
}

void DebugBitsClear(void)
{
	debugmap = 0;
}

const char *mac_display(const UINT8 * mac)
{
	static int etherbuf_index;
	static char etherbuf[72];
	etherbuf_index++;
	etherbuf_index &= 3;
	snprintf(&etherbuf[etherbuf_index * 18], sizeof(etherbuf) / 2, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return &etherbuf[etherbuf_index * 18];
}

static void ToLowerCase(UINT8 * pStr)
{
	UINT16 i;
	UINT16 lenStr = strlen(pStr);

	for (i = 0; i < lenStr; i++) {
		if (*(pStr + i) > 0x40 && *(pStr + i) < 0x5b) {
			*(pStr + i) = *(pStr + i) + 0x20;

		}
	}

}

/*Utility function to convert ascii to a right number.
* Both decimal and hex (beginning with 0x) can be handled.
*/
extern long atohex2(const char *number);
/*{
long   n = 0;

while (*number <= ' ' && *number > 0)
++number;
if (*number == 0)
return n;
if (*number == '0' && (*(number + 1) == 'x' || *(number + 1) == 'X') )
n = atohex(number+2);
else
n = atoi(number);
return n;
}*/
UINT32(*Func0p) (void);
UINT32(*Func1p) (UINT32);
UINT32(*Func2p) (UINT32, UINT32);
UINT32(*Func3p) (UINT32, UINT32, UINT32);
UINT32(*Func4p) (UINT32, UINT32, UINT32, UINT32);

#define MAX_AGRC   11
#define MAX_STRING 128
typedef struct strArray_t {
	UINT8 strArray[MAX_AGRC][MAX_STRING];
} strArray_t;

int StringToArray(UINT8 * string_p, strArray_t * strArray)
{
	UINT16 argc = 0;
	UINT8 *s, *s1;
	UINT8 spacefound = 0;
	UINT16 length = MAX_AGRC * MAX_STRING;
	s = s1 = string_p;
	memset(strArray, 0, sizeof(strArray_t));
	length = strlen(string_p) + 1;
	while (length) {
		if (*s == 0x20 || *s == STRING_TERMINATOR) {
			if (*s == STRING_TERMINATOR) {
				*s = 0;
				strcpy(strArray->strArray[argc++], s1);
				return (argc);
			}
			*s = 0;
			spacefound = 1;
			strcpy(strArray->strArray[argc++], s1);
		}
		s++;
		length--;
		if (spacefound) {
			while (*s == 0x20) {
				length--;
				s++;
			}
			s1 = s;
		}
		spacefound = 0;
	}
	return (argc);
}

void macMgmtMlme_SAQuery(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, IEEEtypes_MacAddr_t * SrcAddr, UINT32 stamode);
int getMacFromString(unsigned char *macAddr, const char *pStr);
extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 *, struct sk_buff *skb, UINT32 rssi);
extern struct sk_buff *ieee80211_getmgtframe(UINT8 ** frm, unsigned int pktlen);
struct ieee80211_frame {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;

struct payload_mgmt {
	UINT16 len;
	UINT8 data[1000];
} PACK;

struct payload_mgmt authAndAssoc[2];

void Debug_Record_Frame_PayLoad(IEEEtypes_Frame_t * fm)
{
	if (fm->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
		if (authAndAssoc[0].len == 0) {
			printk("IEEE_MSG_AUTHENTICATE fm->Hdr.FrmBodyLen=%d, sizeof(IEEEtypes_GenHdr_t)=%zu", fm->Hdr.FrmBodyLen,
			       sizeof(IEEEtypes_GenHdr_t));
			authAndAssoc[0].len = fm->Hdr.FrmBodyLen - sizeof(IEEEtypes_GenHdr_t) + 2;
			memcpy(authAndAssoc[0].data, fm->Body, authAndAssoc[0].len);
			wlDumpData((unsigned char *)__FUNCTION__, authAndAssoc[0].data, authAndAssoc[0].len);
		}
	}

	if (fm->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RQST) {
		if (authAndAssoc[1].len == 0) {
			printk("IEEE_MSG_ASSOCIATE_RQST fm->Hdr.FrmBodyLen=%d, sizeof(IEEEtypes_GenHdr_t)=%zu", fm->Hdr.FrmBodyLen,
			       sizeof(IEEEtypes_GenHdr_t));
			authAndAssoc[1].len = fm->Hdr.FrmBodyLen - sizeof(IEEEtypes_GenHdr_t) + 2;
			memcpy(authAndAssoc[1].data, fm->Body, authAndAssoc[1].len);
			wlDumpData((unsigned char *)__FUNCTION__, authAndAssoc[1].data, authAndAssoc[1].len);
		}
	}

}

BOOLEAN DebugSendMgtMsg(struct net_device *netdev, UINT32 SubtypeAndMore, IEEEtypes_MacAddr_t * DestAddr, IEEEtypes_MacAddr_t * SrcAddr,
			IEEEtypes_MacAddr_t * Bssid, UINT8 * data, UINT16 size)
{
	macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
	struct sk_buff *skb;
	UINT8 *frm;
	UINT32 frameSize = 0;
	UINT32 Subtype = SubtypeAndMore & 0x1ff;
	UINT32 wep = SubtypeAndMore >> 31;
	UINT32 key = SubtypeAndMore >> 30;
#ifndef SOC_W906X
	unsigned long flags;
#endif
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

	if ((skb = ieee80211_getmgtframe(&frm, sizeof(struct ieee80211_frame) + size)) != NULL) {
		WLDBG_INFO(DBG_LEVEL_8, "mlmeApiPrepMgtMsg length = %d \n", skb->len);
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
		MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
		MgmtMsg_p->Hdr.FrmCtl.Subtype = Subtype;
		MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
		MgmtMsg_p->Hdr.FrmCtl.Wep = wep;
		MgmtMsg_p->Hdr.Duration = 300;
		memcpy(&MgmtMsg_p->Hdr.DestAddr, DestAddr, sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr, sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.BssId, Bssid, sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Body.data[0], data, size);
		frameSize = 30 + size;
		skb_trim(skb, frameSize);
#ifdef SOC_W906X
		SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
		if (wlxmit(netdev, skb, IEEE_TYPE_MANAGEMENT | (key << 7) | (1 << 6), NULL, 0, FALSE, 0))
#else
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);
		if (wlxmit(netdev, skb, IEEE_TYPE_MANAGEMENT | (key << 7) | (1 << 6), NULL, 0, FALSE))
#endif
		{
			wl_free_skb(skb);
		}
#ifdef SOC_W906X
		SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
#else
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
#endif
	}
	return TRUE;
}

#ifdef SOC_W906X
void core_dump_file(UINT8 * valbuf, UINT32 length, UINT8 * fname, UINT8 region, UINT32 address, UINT32 append)
#else
void core_dump_file(UINT8 * valbuf, UINT32 length, UINT32 region, UINT32 address, UINT32 append, UINT32 totallen, int textmode)
#endif
{
	struct file *filp_core = NULL;
	char file_name[96];
	UINT8 *buf = (UINT8 *) wl_kmalloc(length * 3, GFP_KERNEL);
	UINT8 *data_p = buf;
	UINT32 i, j = 0;
#ifdef SOC_W906X
	int textmode = 0;
	extern char coredumppath[64];
#endif

	if (!buf)
		return;

	memset(file_name, 0, sizeof(file_name));
#ifdef SOC_W906X
	sprintf(file_name, "%s/coredump_%s_%d", coredumppath, fname, region);
#else
	sprintf(file_name, "/dev/shm/coredump-%x-%x", region, (region + totallen));
#endif

	if (append)
		filp_core = filp_open(file_name, O_RDWR | O_APPEND, 0);
	else {
		filp_core = filp_open(file_name, O_RDWR | O_CREAT | O_TRUNC, 0);
		printk("coredump to %s\n", file_name);
	}

	if (!IS_ERR(filp_core)) {
		if (textmode) {
			for (i = 0; i < length; i += 4) {
				volatile unsigned int val = 0;

				val = *(unsigned int *)(&valbuf[i]);

				if (i % 16 == 0) {
					sprintf(buf + j, "\n0x%08x", (int)(address + i));
					j = strlen(buf);
				}
				sprintf(buf + j, "  %08x", val);
				j = strlen(buf);
			}
			data_p = buf + j;
			data_p += sprintf(data_p, "\n");
			__kernel_write(filp_core, buf, strlen(buf), &filp_core->f_pos);
		} else {
			__kernel_write(filp_core, valbuf, length, &filp_core->f_pos);
		}
		filp_close(filp_core, current->files);
	} else {
		pr_err("Open %s failed: errno %ld\n", file_name, PTR_ERR(filp_core));
	}
	wl_kfree(buf);
}

u64 dump_file(UINT8 * valbuf, UINT32 length, UINT8 * fname, UINT32 append)
{
	struct file *filp_core = NULL;
	u64 pos = 0;

	if (fname == NULL)
		return 0;

	if (append) {
		filp_core = filp_open(fname, O_RDWR | O_CREAT | O_APPEND, 0);
		//printk("dump append to %s\n",fname);
	} else {
		filp_core = filp_open(fname, O_RDWR | O_CREAT | O_TRUNC, 0);
		//printk("coredump to %s\n",fname);
	}

	if (!IS_ERR(filp_core)) {
		__kernel_write(filp_core, valbuf, strlen(valbuf), &filp_core->f_pos);
		pos = filp_core->f_pos;
		filp_close(filp_core, current->files);
	} else {
		printk("open dump file fail...\n");
	}

	return pos;
}

u64 dump_binfile(UINT8 * valbuf, UINT32 length, UINT8 * fname, UINT32 append)
{
	struct file *filp_core = NULL;
	u64 pos = 0;

	if (fname == NULL)
		return 0;
	if (append) {
		filp_core = filp_open(fname, O_RDWR | O_CREAT | O_APPEND, 0);
	} else {
		filp_core = filp_open(fname, O_RDWR | O_CREAT | O_TRUNC, 0);
	}
	if (!IS_ERR(filp_core)) {
		__kernel_write(filp_core, valbuf, length, &filp_core->f_pos);
		pos = filp_core->f_pos;
		filp_close(filp_core, current->files);
	} else {
		printk("open dump bin file fail...\n");
	}
	return pos;
}

u64 read_binfile(UINT8 * valbuf, UINT32 length, UINT8 * fname)
{
	struct file *filp_core = NULL;
	u64 pos = 0;

	if (fname == NULL)
		return 0;
	filp_core = filp_open(fname, O_RDONLY, 0);
	if (IS_ERR(filp_core)) {
		printk("open read file [%s] fail...\n", fname);
		goto funcfinal;
	}
	kernel_read(filp_core, valbuf, length, &filp_core->f_pos);
	filp_close(filp_core, current->files);
 funcfinal:
	return pos;
}

extern u_int32_t debug_tcpack;
extern UINT32 vht_cap;
extern UINT32 SupportedRxVhtMcsSet;
//extern UINT32 SupportedTxVhtMcsSet;
extern UINT32 ch_width;
extern UINT32 center_freq0;
extern UINT32 center_freq1;
extern UINT32 basic_vht_mcs;
extern UINT32 dbg_level;
extern UINT32 dbg_class;
#ifdef CAP_MAX_RATE
extern u_int32_t MCSCapEnable;
extern u_int32_t MCSCap;
#endif
char DebugData[1000];

#ifdef SOC_W906X
extern void wl_set_da(UINT32 * sta_mac);
extern void wl_set_qm_sa(IEEEtypes_MacAddr_t StaMacAddr);
static void setStaPeerInfo(PeerInfo_t * pPeerInfo, UINT8 ApMode, UINT8 nss, UINT8 bw, UINT8 gi);
#endif

void dfs_print_array(struct net_device *netdev, U8 isBusTypeMCI, char *title, UINT16 location, UINT16 length, UINT32 mem_addr)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 *valbuf;
	int i, dwordNum, segMax, seg;

	if ((length == 0) || (mem_addr == 0)) {
		printk("[ERROR] Input %s length=%d mem_addr=0x%08x\n", title, length, mem_addr);
		return;
	}
	dwordNum = (length + 3) / 4;
	segMax = (dwordNum + 63) / 64;

	valbuf = wl_kmalloc(sizeof(UINT32) * 64, GFP_KERNEL);
	if (valbuf == NULL) {
		printk("[ERROR] Allocate memory 256 bytes failed\n");
		return;
	}
	printk("\n[%s] address= 0x%08x length = %d bytes \n", title, mem_addr, length);

	if (location == DFS_LOC_DMEM) {
		UINT32 offset = mem_addr & 0x0ffffffc;

		if (!isBusTypeMCI && (offset + length) > 0x100000) {	//over iobase0 remap boundary. PCIE BAR0 1M.                                                                
			printk("memory over pcie iobase0(BAR0) boundary , read through cmd path.\n");

			for (seg = 0; seg < segMax; seg++) {
				if (wlFwGetAddrValue(netdev, (SMAC_DMEM_START + offset + seg * 64 * 4), 64, &valbuf[0], 0)) {
					printk("Could not get the memory address value\n");
					wl_kfree(valbuf);
					return;
				}
				for (i = 0; i < MIN(dwordNum, 64); i++) {
					if ((i % 4) == 0) {
						printk("\n0x%08x", (u32) (SMAC_DMEM_START + offset + (seg * 256) + (i * 4)));
					}
					printk("  %08x", valbuf[i]);
				}
				dwordNum -= 64;
			}
		} else {
			for (seg = 0; seg < segMax; seg++) {
				for (i = 0; i < 64; i++) {
					volatile unsigned int val = 0;

					valbuf[i] = val = le32_to_cpu(*(volatile unsigned int *)(priv->ioBase0 + offset + (seg * 256) + (i * 4)));
				}
				for (i = 0; i < MIN(dwordNum, 64); i++) {
					if (i % 4 == 0) {
						printk("\n0x%08x", (int)(0x20000000 + (seg * 256) + offset + (i * 4)));
					}
					printk("  %08x", valbuf[i]);
				}
				dwordNum -= 64;
			}
		}
	} else			//DFS_LOC_IRAM     
	{
		for (seg = 0; seg < segMax; seg++) {
			if (wlFwGetAddrValue(netdev, (mem_addr + seg * 256), 64, &valbuf[0], 0)) {
				printk("Could not get the memory address value\n");
				wl_kfree(valbuf);
				return;
			}
			for (i = 0; i < MIN(dwordNum, 64); i++) {
				if ((i % 4) == 0) {
					printk("\n0x%08x", (u32) (mem_addr + (seg * 256) + (i * 4)));
				}
				printk("  %08x", valbuf[i]);
			}
			dwordNum -= 64;
		}
	}
	printk("\n");
	wl_kfree(valbuf);
}

UINT8 DebugCmdParse(struct net_device *netdev, UINT8 * str)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_STA_CFG *mib_StaCfg = mib->StationConfig;
	UINT16 argc;
	strArray_t *strArray_p;
	strArray_p = mymalloc(sizeof(strArray_t));
	if (strArray_p == NULL)
		return 1;
	ToLowerCase(str);
	argc = StringToArray(str, strArray_p);

#ifdef SOC_W906X
	if (!memcmp(strArray_p->strArray[0], "dropsta", 6)) {
		wlFwTxDropMode(netdev, atohex2(strArray_p->strArray[1]), 1, atohex2(strArray_p->strArray[2]));
	}
#ifdef DEBUG_BAREORDER

	//print out of range BA reorder log
	else if (!memcmp(strArray_p->strArray[0], "reorderprint", 12)) {
		UINT32 i;
		char str[7][8] = { "tmo", "seqno", "OOR", "OOR_rpt", "store", "wEnd", "bar" };

		printk("wdev:%d, staid:%d\n", dbg_BAredr_cardindex, dbg_BAredr_id);

		for (i = 0; i < 7; i++) {
			printk("Tag %10s: 0x%x", str[i], (dbg_BAredr_tag[i] & 0xFFFFFF00));

			if (strcmp(str[i], "tmo") == 0) {
				printk("\tb31-28:tid, b27-20:bufCnt, b19-8:winStartB, b7-0: drpCnt\n");
			} else {
				printk("\tb31-28:tid, b27-24:info, b23-12:winStartB, b11-0: seqNo\n");
			}
		}
		printk("History log, starting from oldest to latest \n");
		for (i = 0; i <= DBG_BAREORDER_LOG_MASK; i++) {
			if ((i % 4) == 0) {
				printk("\n");
				printk("log");
			}

			printk("\t");
			printk("0x%08X", dbg_BAredr_log[i]);
		}
		printk("\n\n");
	}
	//change BA reorder wdev and sta id for logging
	else if (!memcmp(strArray_p->strArray[0], "reorderid", 9)) {
		UINT32 i, cardindex;
		struct wlprivate *wlpptr;

		if (priv->master) {
			wlpptr = NETDEV_PRIV_P(struct wlprivate, priv->master);
			cardindex = wlpptr->cardindex;
		} else {
			cardindex = priv->cardindex;
		}

		dbg_BAredr_cardindex = 0xFFFF;	//stop all logging before reset
		dbg_BAredr_id = 0xFFFF;

		dbg_BAredr_log_cnt = 0;

		for (i = 0; i <= DBG_BAREORDER_LOG_MASK; i++) {
			dbg_BAredr_log[i] = 0;
			if (i <= DBG_BAREORDER_SN_MASK) {
				dbg_BAredr_SN[i] = 0;
			}
		}

		dbg_BAredr_cardindex = cardindex;
		dbg_BAredr_id = atohex2(strArray_p->strArray[1]);
		printk("log for wdev:%d, staid:%d\n", dbg_BAredr_cardindex, dbg_BAredr_id);
	}
	//pick which area of BA reorder for logging in bitmap
	else if (!memcmp(strArray_p->strArray[0], "reorderbmap", 11)) {
		UINT8 mask, i, print = 0;
		char str[7][8] = { "tmo", "seqno", "OOR", "OOR_rpt", "store", "wEnd", "bar" };

		if (!memcmp(strArray_p->strArray[1], "\0", 1)) {
			printk("Enter bmap to enable logging\n");
			printk("b6:bar, b5:wEnd, b4:store, b3:OOR rpt, b2:OOR, b1: seqno: b0: tmo\n");
		} else {
			mask = atohex2(strArray_p->strArray[1]);
			mask &= DBG_BAREORDER_MASK;
			dbg_BAredr_log_en_mask = mask;

			if (mask == 0) {
				printk("BA reorder log disabled\n");
			} else {
				printk("BA reorder log mask 0x%x\n", dbg_BAredr_log_en_mask);

				i = 0;
				while (mask) {
					if ((mask >> i) & 0x1) {
						if (print == 0) {
							printk("Logs enabled for %s", str[i]);
							print = 1;
						} else {
							printk(", %s", str[i]);
						}
						mask &= (mask - 1);
					}
					i++;
				}
				printk("\n");
			}
		}
	}
	//set num of history look back to add into log
	else if (!memcmp(strArray_p->strArray[0], "reorderhist", 11)) {
		UINT8 index, val;
		char str[7][8] = { "tmo", "seqno", "OOR", "OOR_rpt", "store", "wEnd", "bar" };

		if (!memcmp(strArray_p->strArray[1], "\0", 1)) {
			printk("Enter [index < 7] [history log cnt <= %d]\n\n", DBG_BAREORDER_SN_MASK);
			printk("index 0 to 7: tmo, seqno, OOR, OOR rpt, store, wEnd, bar\n\n");

		} else {
			index = atohex2(strArray_p->strArray[1]);
			if (index >= 7) {
				printk("Enter index < 7\n");
				printk("index 0 to 7: tmo, seqno, OOR, OOR rpt, store, wEnd, bar\n\n");
				return 1;
			}

			if (!memcmp(strArray_p->strArray[2], "\0", 1)) {
				printk("Log history cnt is missing\n\n");
				printk("Enter [index < 7] [history log cnt <= %d]\n", DBG_BAREORDER_SN_MASK);
				printk("index 0 to 7: tmo, seqno, OOR, OOR rpt, store, wEnd, bar\n\n");
				return 1;
			}

			val = atohex2(strArray_p->strArray[2]);
			if (val > DBG_BAREORDER_SN_MASK) {
				val = DBG_BAREORDER_SN_MASK;
			}

			dbg_BAredr_hist_log[index] = val;
			printk("History log cnt for:\n");
			for (index = 0; index < 7; index++) {
				printk("%s: %d\n", str[index], dbg_BAredr_hist_log[index]);
			}
		}
	}
	//reset log to 0
	else if (!memcmp(strArray_p->strArray[0], "reorderreset", 12)) {
		UINT32 i, temp1, temp2;

		temp1 = dbg_BAredr_cardindex;
		temp2 = dbg_BAredr_id;

		dbg_BAredr_cardindex = 0xFFFF;	//stop all logging before reset
		dbg_BAredr_id = 0xFFFF;

		dbg_BAredr_log_cnt = 0;

		for (i = 0; i <= DBG_BAREORDER_LOG_MASK; i++) {
			dbg_BAredr_log[i] = 0;
			if (i <= DBG_BAREORDER_SN_MASK) {
				dbg_BAredr_SN[i] = 0;
			}
		}

		dbg_BAredr_cardindex = temp1;	//restore original id for logging
		dbg_BAredr_id = temp2;
	}
#endif

	else if (!memcmp(strArray_p->strArray[0], "reorder", 7)) {
		priv->wlpd_p->fastdata_reordering_disable = atohex2(strArray_p->strArray[1]) ? 0 : 1;
		printk("Fast Data Reordering %s\n", priv->wlpd_p->fastdata_reordering_disable ? "Disabled" : "Enabled");
	} else if (!memcmp(strArray_p->strArray[0], "droptxq", 6)) {
		wlFwTxDropMode(netdev, atohex2(strArray_p->strArray[1]), 0, atohex2(strArray_p->strArray[2]));
	} else if (!memcmp(strArray_p->strArray[0], "coredumpmode", 12)) {
		triggerCoredump(netdev);
	} else if (!memcmp(strArray_p->strArray[0], "coredump", 8)) {
		struct notifier_block smac_monitor_notifier_nb;

		smac_monitor_notifier_nb.notifier_call = wldbgCoreDump;
		//set action=0 for call manually.
		wldbgCoreDump(&smac_monitor_notifier_nb, 0, (void *)netdev);
	} else if (!memcmp(strArray_p->strArray[0], "coresniff", 9)) {
		coredump_cmd_t *core_dump = NULL;
		coredump_t *cd;
		char *buff = NULL;
		UINT32 offset, regionIdx, dumpOffset, dumpLength, append = 0;
		char fname[16] = { 0 };
		UINT32 time = 0;

		cd = (coredump_t *) & priv->wlpd_p->coredump;

		printk("coresniff started\n");
		do {
			core_dump = (coredump_cmd_t *) wl_kmalloc(sizeof(coredump_cmd_t), GFP_ATOMIC);
			if (!core_dump) {
				printk("Error[%s:%d]: Allocating F/W Core Dump Memory \n", __func__, __LINE__);
				break;
			}

			buff = (char *)wl_kmalloc(MAX_CORE_DUMP_BUFFER, GFP_ATOMIC);
			if (!buff) {
				printk("Error[%s:%d]: Allocating F/W Buffer for Core Dump \n", __func__, __LINE__);
				break;
			}

			memset((char *)buff, 0, MAX_CORE_DUMP_BUFFER);
			time = (UINT32) xxGetTimeStamp();	//use last word partial fileanme
			sprintf(fname, "%08x", time);

			regionIdx = atohex2(strArray_p->strArray[1]);
			if (regionIdx >= cd->num_regions) {
				printk("Error[%s:%d]: regionIdx beyonds max region number %d \n", __func__, __LINE__, cd->num_regions);
				break;
			}

			dumpOffset = atohex2(strArray_p->strArray[2]);
			if (dumpOffset >= cd->region[regionIdx].length) {
				printk("Error[%s:%d]: dumpOffset beyonds max region length %d \n", __func__, __LINE__, cd->region[regionIdx].length);
				break;
			}

			dumpLength = atohex2(strArray_p->strArray[3]);
			if (!dumpLength)	// if dumplength is 0, then dump to the end of the region
				dumpLength = cd->region[regionIdx].length - dumpOffset;

			core_dump->context = ((regionIdx & 0x1f) << 27) | (dumpOffset & 0x7ffffff);
			core_dump->buffer = (u32) (*buff);
			core_dump->buffer_len = MAX_CORE_DUMP_BUFFER;

			for (offset = dumpOffset; offset < dumpOffset + dumpLength;) {
				core_dump->context = ((regionIdx & 0x1f) << 27) | (offset & 0x7ffffff);
				core_dump->flags = 0;
				core_dump->sizeB = (dumpLength > MAX_CORE_DUMP_BUFFER) ? MAX_CORE_DUMP_BUFFER : dumpLength;
				offset += core_dump->sizeB;
				printk("%s", ".");
				if (wlFwGetCoreSniff(netdev, core_dump, buff) == FAIL) {
					printk("Error[%s:%d]: Failed to get Core Dump offset %x\n", __func__, __LINE__, offset);
					break;
				}
				core_dump_file(buff, core_dump->sizeB, fname, regionIdx, cd->region[regionIdx].address + offset, append++);
			}

		} while (0);
		if (buff)
			wl_kfree(buff);

		if (core_dump)
			wl_kfree(core_dump);
	} else if (!memcmp(strArray_p->strArray[0], "addbss", 6)) {
		wlFwSetApBeacon(netdev);
		wlFwSetAPBss(netdev, WL_ENABLE);
	} else if (!memcmp(strArray_p->strArray[0], "qid-tx", 7)) {
		extern UINT32 drv_self_test_qid_enable;
		extern UINT32 drv_self_test_qid;

		drv_self_test_qid_enable = atohex2(strArray_p->strArray[1]);
		drv_self_test_qid = atohex2(strArray_p->strArray[2]);
		printk("%s debugging Tx Qid %d\n", drv_self_test_qid_enable ? "Enable" : "Disable", drv_self_test_qid);
	} else if (!memcmp(strArray_p->strArray[0], "tbl-sta", 7)) {
		TXD_STA_t *gTxdSta;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 index = atohex2(strArray_p->strArray[2]);
		UINT32 temp[sizeof(TXD_STA_t) / 4];
		int i;

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		if ((address > 0xC0000000) || (index > 0x1000)) {
			netdev_alert(netdev, "invalid address %#08x or index %u\n", address, index);
			goto out;
		}

		gTxdSta = (TXD_STA_t *) (address + priv->ioBase0);

		memcpy((void *)&temp, (void *)&gTxdSta[index], sizeof(temp));

		printk("\nsta table = %d address = %p\n", index, &gTxdSta[index]);

		for (i = 0; i < sizeof(temp) / 4; i++)
			temp[i] = ENDIAN_SWAP32(temp[i]);

		gTxdSta = (TXD_STA_t *) temp;

		printk("raLow        : %08x\n", gTxdSta->raLow);
		printk("raHigh       : %08x\n", gTxdSta->raHigh);
		printk("txLimitIndex : %d\n", gTxdSta->txLimitIndex);
		printk("markDropRate : 0x%02x\n", gTxdSta->markDropRate);
		printk("l0SizeDw     : %d\n", gTxdSta->l0SizeDw);
		printk("l0SizePkt    : %d\n", gTxdSta->l0SizePkt);

		printk("bssIndex     : %d\n", gTxdSta->bssIndex);
		printk("vlanId       : %d\n", gTxdSta->vlanId);
		printk("vlanMode     : %d\n", gTxdSta->vlanMode);
		printk("maxMtu       : %d\n", gTxdSta->maxMtu);
		printk("forceDa      : %d\n", gTxdSta->forceDa);
		printk("ecnEnable    : %d\n", gTxdSta->ecnEnable);
	} else if (!memcmp(strArray_p->strArray[0], "tbl-bss", 7)) {
		TXD_BSS_t *gTxdBss;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 index = atohex2(strArray_p->strArray[2]);
		UINT32 temp[sizeof(TXD_BSS_t) / 4];
		int i;

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		if ((address > 0xC0000000) || (index > 0x1000)) {
			netdev_alert(netdev, "invalid address %#08x or index %u\n", address, index);
			goto out;
		}

		gTxdBss = (TXD_BSS_t *) (address + priv->ioBase0);

		memcpy((void *)&temp, (void *)&gTxdBss[index], sizeof(temp));

		printk("\nbss table = %d address = %p\n", index, &gTxdBss[index]);

		for (i = 0; i < sizeof(temp) / 4; i++)
			temp[i] = ENDIAN_SWAP32(temp[i]);

		gTxdBss = (TXD_BSS_t *) temp;

		printk("taLow        : 0x%08x\n", gTxdBss->taLow);
		printk("taHigh       : 0x%08x\n", gTxdBss->taHigh);
		printk("txLimitIndex : %d\n", gTxdBss->txLimitIndex);
		printk("markDropRate : 0x%02x\n", gTxdBss->markDropRate);
		printk("l0SizeDw     : %d\n", gTxdBss->l0SizeDw);
		printk("l0SizePkt    : %d\n", gTxdBss->l0SizePkt);

		printk("vlanId       : %d\n", gTxdBss->vlanId);
		printk("vlanMode     : %d\n", gTxdBss->vlanMode);
		printk("maxMtu       : %d\n", gTxdBss->maxMtu);
		printk("forceSa      : %d\n", gTxdBss->forceSa);
	}
#if 0
	else if (!memcmp(strArray_p->strArray[0], "dump-ddr", 8)) {
		extern void mwl_hex_dump(const void *buf, size_t len);
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 length = atohex2(strArray_p->strArray[2]);

		//address = phys_to_virt(address);
		mwl_hex_dump(phys_to_virt(address), length);
	}
#endif
	else if (!memcmp(strArray_p->strArray[0], "tbl-txq", 7)) {
		TXD_TXQ_t *gTxdTxq;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 index = atohex2(strArray_p->strArray[2]);
		UINT32 *temp;
		int i;

		temp = wl_kmalloc(sizeof(TXD_TXQ_t) * SMAC_QID_PER_STA + 4, GFP_KERNEL);

		if (temp == NULL) {
			printk("Failed to alloc TXD_TXQ_t space size = %d\n", (int)sizeof(TXD_TXQ_t) * SMAC_QID_PER_STA);
			goto out;
		}

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		if ((address > 0xC0000000) || (index > 0x1000)) {
			if (temp)
				wl_kfree(temp);

			netdev_alert(netdev, "invalid address %#08x or index %u\n", address, index);
			goto out;
		}

		gTxdTxq = (TXD_TXQ_t *) (address + priv->ioBase0);

		memcpy((void *)temp, (void *)&gTxdTxq[index], sizeof(TXD_TXQ_t) * SMAC_QID_PER_STA);

		printk("txq table qid = %d - %d address = %p\n", index, (index + SMAC_QID_PER_STA - 1), &gTxdTxq[index]);

		for (i = 0; i < (sizeof(TXD_TXQ_t) * SMAC_QID_PER_STA) / 4; i++)
			temp[i] = ENDIAN_SWAP32(temp[i]);

		gTxdTxq = (TXD_TXQ_t *) temp;

		//DW0
		printk("\nisShortAmsdu       : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].isShortAmsdu);	//0:normal AMSDU, 1:Short AMSDU

		printk("\nisBss              : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].isBss);	//0:STA index, 1:BSS index

		printk("\nblk0Wrptr          : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%08x  ", gTxdTxq[i].blk0Wrptr);	//L0 Write pointer   

		//DW1
		printk("\nlowLatencyTrigStat : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].lowLatencyTrigStat);

		printk("\nblk1Wrptr          : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%08x  ", gTxdTxq[i].blk1Wrptr);	//L1: write pointer

		printk("\nstaBssIndex        : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].staBssIndex);

		printk("\nl0SizeDw           : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].l0SizeDw);

		printk("\nl0SizePkt          : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].l0SizePkt);	//[packet]

		printk("\npktInsertTsf       : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].pktInsertTsf);	// TSF[16:3] at last packet insert  

		printk("\nl0DropSizeDw       : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].l0DropSizeDw);

		printk("\nl0DropSizePkt      : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].l0DropSizePkt);	//[packet]

		printk("\ntrigThresDw        : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].trigThresDw);	//[DWORD] mantissa(4b)+exponent(4b)

		printk("\ntrigThresPkt       : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].trigThresPkt);	//[packet]mantissa(4b)+exponent(4b)
		printk("\nmarkDropRate       : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].markDropRate);

		printk("\ntxLimitIndex       : ");
		for (i = 0; i < SMAC_QID_PER_STA; i++)
			printk("%8d  ", gTxdTxq[i].txLimitIndex);	//for Tx Limit Table

		printk("\n\n");
		wl_kfree(temp);
	} else if (!memcmp(strArray_p->strArray[0], "dfs-log", 7)) {
		extern void dfsTraceLogPrint(UINT8 idx, DfsAp * pdfsApMain);
		DfsAp *pdfsApMain = priv->wlpd_p->pdfsApMain;
		struct pkttype_info *wlpkt_tx = &priv->wlpd_p->tpkt_type_cnt;
		struct pkttype_info *wlpkt_rx = &priv->wlpd_p->rpkt_type_cnt;

		if (pdfsApMain) {
			int print_drv = TRUE;
			int print_fw = TRUE;

			if (!memcmp(strArray_p->strArray[1], "drv", 3)) {
				print_fw = FALSE;
			} else if (!memcmp(strArray_p->strArray[1], "fw", 2)) {
				print_drv = FALSE;
			}

			if (print_drv) {
				struct net_device_stats *stat;

				if (priv->vmacSta_p->master)
					stat = &(priv->netDevStats);
				else {
					get_phyif_device_stats(netdev);
					stat = &(priv->phyif_netDevStats);
				}

				printk("[DFS]: dropData         = %u\n", pdfsApMain->dropData);
				printk("[DFS]: tx_dropped       = %lu\n", stat->tx_dropped);
				printk("[DFS]: rx prob_req_cnt  = %u\n", wlpkt_rx->prob_req_cnt);
				printk("[DFS]: tx prob_resp_cnt = %u\n", wlpkt_tx->prob_resp_cnt);
				printk("[DFS]: buffer_full_cnt  = %u\n", wlpd_p->drv_stats_val.txq_full_cnt);
				printk("[DFS]: sent_cnt         = %u\n", wlpd_p->drv_stats_val.txq_drv_sent_cnt);
				printk("\n");
				dfsTraceLogPrint(vmacSta_p->VMacEntry.phyHwMacIndx, pdfsApMain);
			}
			if (print_fw) {
				extern int wlFwDFSParamsLog(struct net_device *netdev, UINT16 Action, dfs_log_t * pLog);
				dfs_log_t dfslog;
				U8 isBusTypeMCI = IS_BUS_TYPE_MCI(priv);

				wlFwDFSParamsLog(netdev, DFS_GET_LOG, &dfslog);

				printk("***** DFS Firmware Log *******\n");
				// Primary Channel Info
				printk("dfsRegDomain            = %d  \n", dfslog.dfsRegDomain);
				printk("dfs_curr_region         = 0x%x\n", dfslog.dfs_curr_region);
				printk("dfs_w53_flag            = %d  \n", dfslog.dfs_w53_flag);
				printk("\n[DFS_MAIN]\n");
				printk("dfs_rdwr                = 0x%08x\n", dfslog.dfs_rdwr[DFS_MAIN]);
				printk("dfs_curr_state          = %s \n", dfslog.dfs_curr_state[DFS_MAIN] ? "enable" : "disable");
				printk("dfs_cac_state           = %s \n", dfslog.dfs_cac_state[DFS_MAIN] ? "enable" : "disable");
				printk("dfs_curr_chan           = %d bandwidth = %d\n", dfslog.dfs_curr_chan[DFS_MAIN], dfslog.dfs_dbg_bw[DFS_MAIN]);
				printk("dfs_que_thread          = %d\n", dfslog.dfs_que_thread[DFS_MAIN]);
				printk("dfs_event_main          = %d\n", dfslog.dfs_event_main);
				printk("dfs_time_main           = %d\n", dfslog.dfs_time_main);
				printk("dfs_full_main           = %d\n", dfslog.dfs_full_main);
				//      
				printk("hal_dfsRadarDetected    = 0x%08x\n", dfslog.hal_dfsRadarDetected[DFS_MAIN]);
				printk("hal_dfsChirpRadarCnt    = 0x%08x\n", dfslog.hal_dfsChirpRadarCnt[DFS_MAIN]);
				printk("hal_dfsFixRadarCnt      = 0x%08x\n", dfslog.hal_dfsFixRadarCnt[DFS_MAIN]);
				printk("hal_dfsFalseRadarCnt    = 0x%08x\n", dfslog.hal_dfsFalseRadarCnt[DFS_MAIN]);
				printk("hal_dfsRecordProcessed  = 0x%08x\n", dfslog.hal_dfsRecordProcessed[DFS_MAIN]);
				printk("false_chirp_radar_count = 0x%08x\n", dfslog.false_chirp_radar_count[DFS_MAIN]);
				printk("false_det_count_history = 0x%08x\n", dfslog.false_det_count_history[DFS_MAIN]);
				// Scendary Channel Info
				printk("\n[DFS_AUX]\n");
				printk("dfs_rdwr                = 0x%08x\n", dfslog.dfs_rdwr[DFS_AUX]);
				printk("dfs_curr_state          = %s \n", dfslog.dfs_curr_state[DFS_AUX] ? "enable" : "disable");
				printk("dfs_cac_state           = %s \n", dfslog.dfs_cac_state[DFS_AUX] ? "enable" : "disable");
				printk("dfs_curr_chan           = %d bandwidth = %d\n", dfslog.dfs_curr_chan[DFS_AUX], dfslog.dfs_dbg_bw[DFS_AUX]);
				printk("dfs_que_thread          = %d\n", dfslog.dfs_que_thread[DFS_AUX]);
				printk("dfs_event_sep           = %d\n", dfslog.dfs_event_sep);
				printk("dfs_time_sep            = %d\n", dfslog.dfs_time_sep);
				printk("dfs_full_sep            = %d\n", dfslog.dfs_full_sep);
				//
				printk("hal_dfsRadarDetected    = 0x%08x\n", dfslog.hal_dfsRadarDetected[DFS_AUX]);
				printk("hal_dfsChirpRadarCnt    = 0x%08x\n", dfslog.hal_dfsChirpRadarCnt[DFS_AUX]);
				printk("hal_dfsFixRadarCnt      = 0x%08x\n", dfslog.hal_dfsFixRadarCnt[DFS_AUX]);
				printk("hal_dfsFalseRadarCnt    = 0x%08x\n", dfslog.hal_dfsFalseRadarCnt[DFS_AUX]);
				printk("hal_dfsRecordProcessed  = 0x%08x\n", dfslog.hal_dfsRecordProcessed[DFS_AUX]);
				printk("false_chirp_radar_count = 0x%08x\n", dfslog.false_chirp_radar_count[DFS_AUX]);
				printk("false_det_count_history = 0x%08x\n", dfslog.false_det_count_history[DFS_AUX]);

				dfs_print_array(netdev, isBusTypeMCI, "Pri_save", dfslog.loc_Pri_save, dfslog.len_Pri_save, dfslog.Pri_save_addr);
				dfs_print_array(netdev, isBusTypeMCI, "ZC_save", dfslog.loc_ZC_save, dfslog.len_ZC_save, dfslog.ZC_save_addr);
				dfs_print_array(netdev, isBusTypeMCI, "chirp_freq_data_save", dfslog.loc_chirp_freq_data_save,
						dfslog.len_chirp_freq_data_save, dfslog.chirp_freq_data_save_addr);
				dfs_print_array(netdev, isBusTypeMCI, "dfs_dbg_cnt", dfslog.loc_dfs_dbg_cnt, dfslog.len_dfs_dbg_cnt,
						dfslog.dfs_dbg_cnt_addr);

				dfs_print_array(netdev, isBusTypeMCI, "dfs_status", dfslog.loc_dfs_status, dfslog.len_dfs_status,
						dfslog.dfs_status_addr);
				dfs_print_array(netdev, isBusTypeMCI, "dfs_radar", dfslog.loc_dfs_radar, dfslog.len_dfs_radar, dfslog.dfs_radar_addr);
				dfs_print_array(netdev, isBusTypeMCI, "dfsQmem", dfslog.loc_dfsQmem, dfslog.len_dfsQmem, dfslog.dfsQmem_addr);
			}
		} else {
			printk("[DFS] not enabled\n");
		}
	} else if (!memcmp(strArray_p->strArray[0], "smac-tbl-sta", 12)) {
		SMAC_STA_ENTRY_st *gSta;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 index = atohex2(strArray_p->strArray[2]);
		UINT32 *temp;
		int i;

		temp = wl_kmalloc(sizeof(SMAC_STA_ENTRY_st) + 4, GFP_KERNEL);

		if (temp == NULL) {
			printk("Failed to alloc SMAC_STA_ENTRY_st space size = %d\n", (int)sizeof(SMAC_STA_ENTRY_st));
			goto out;
		}

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		if ((address > 0xC0000000) || (index > 0x1000)) {
			if (temp)
				wl_kfree(temp);

			netdev_alert(netdev, "invalid address %#08x or index %u\n", address, index);
			goto out;
		}

		gSta = (SMAC_STA_ENTRY_st *) (address + priv->ioBase0);

		memcpy((void *)temp, (void *)&gSta[index], sizeof(SMAC_STA_ENTRY_st));

		printk("\nsta table = %d address = %p size=%d\n", index, &gSta[index], (int)sizeof(SMAC_STA_ENTRY_st));

		for (i = 0; i < sizeof(SMAC_STA_ENTRY_st) / 4; i++)
			temp[i] = ENDIAN_SWAP32(temp[i]);

		gSta = (SMAC_STA_ENTRY_st *) temp;

		printk("txMode                      : %d\n", gSta->txMode);
		printk("shortPreamble               : %d\n", gSta->shortPreamble);
		printk("maxAmsduLen                 : %d\n", gSta->maxAmsduLen);
		printk("mmssByte                    : %d\n", gSta->mmssByte);
		printk("rateMcs                     : 0x%02x\n", gSta->rateMcs);
		printk("rtsRate                     : 0x%02x\n", gSta->rtsRate);
		printk("stbc                        : %d\n", gSta->stbc);
		printk("nDltf                       : %d\n", gSta->nDltf);
		printk("nEss                        : %d\n", gSta->nEss);
		printk("nSts                        : %d\n", gSta->nSts);
		printk("shortGi                     : %d\n", gSta->shortGi);
		printk("fecCode                     : %d\n", gSta->fecCode);
		printk("nEs                         : %d\n", gSta->nEs);
		printk("bw                          : %d\n", gSta->bw);
		//printk("amsduSupported              : %d\n", gSta->amsduSupported);
		printk("amsduSupported              : %d\n", gSta->minAmsduSubframe);
		printk("nDbps                       : %d\n", gSta->nDbps);
		printk("mmss                        : %d\n", gSta->mmss);
		printk("tPreamble                   : %d\n", gSta->tPreamble);
		printk("maxAmpduLen                 : %d\n", gSta->maxAmpduLen);
		printk("aid                         : %d\n", gSta->aid);
		printk("euModeCtrl                  : 0x%04x\n", gSta->euModeCtrl);
		printk("euMode                      : %d\n", gSta->euMode);
		printk("keyId                       : %d - %d\n", gSta->keyId[0], gSta->keyId[1]);
		printk("key[0]                      : %08x %08x %08x %08x\n", gSta->key[0][0], gSta->key[0][1], gSta->key[0][2], gSta->key[0][3]);
		printk("                            : %08x %08x %08x %08x\n", gSta->key[0][4], gSta->key[0][5], gSta->key[0][6], gSta->key[0][7]);
		printk("key[1]                      : %08x %08x %08x %08x\n", gSta->key[1][0], gSta->key[1][1], gSta->key[1][2], gSta->key[1][3]);
		printk("                            : %08x %08x %08x %08x\n", gSta->key[1][4], gSta->key[1][5], gSta->key[1][6], gSta->key[1][7]);
		printk("keyRecIdx                   : %d\n", gSta->keyRecIdx);
		printk("pn_inc                      : %d\n", gSta->pn_inc);
		printk("txd4Overload                : %d\n", gSta->txd4Overload);
		printk("pn[0-7]                     : %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n", gSta->pn[0], gSta->pn[1], gSta->pn[2], gSta->pn[3],
		       gSta->pn[4], gSta->pn[5], gSta->pn[6], gSta->pn[7]);
		printk("pn[8-15]                    : %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n", gSta->pn[8], gSta->pn[9], gSta->pn[10],
		       gSta->pn[11], gSta->pn[12], gSta->pn[13], gSta->pn[14], gSta->pn[15]);
		printk("qosMask                     : 0x%x\n", gSta->qosMask);
		printk("muGrpId                     : %d\n", gSta->muGrpId);
		printk("bssidInfo                   : 0x%0x8\n", gSta->bssidInfo);
		printk("state                       : %d\n", gSta->state);
		printk("mfpEnabled                  : %d\n", gSta->mfpEnabled);
		//U16 lastSeqCtrl[16+3];         ///< 0-15:QoS Data, 16-non-QoS, 17-mgmt, 18-mgmtTimePriority
		printk("baInfoDdrAddr               : 0x%08x\n", gSta->baInfoDdrAddr);
		printk("psmpState                   : %d\n", gSta->psmpState);
		printk("dualCtsProtection           : %d\n", gSta->dualCtsProtection);
		printk("macAddr                     : %02x:%02x:%02x:%02x:%02x:%02x\n", gSta->macAddr[0], gSta->macAddr[1], gSta->macAddr[2],
		       gSta->macAddr[3], gSta->macAddr[4], gSta->macAddr[5]);
		printk("maxAmsduSubframesConf       : 0x%x\n", gSta->maxAmsduSubframesConf);
		printk("maxAmsduSubframesUsing      : %d\n", gSta->maxAmsduSubframesUsing);	///< Currently used by FW. This is recalculated based on rate  
		printk("DSbit                       : %d\n", gSta->DSbit);
		printk("pwrState                    : %d\n", gSta->pwrState);
		printk("rxBa.pbac                   : 0x%x\n", gSta->rxBa.pbac);
		printk("rxBa.htCapa                 : %d\n", gSta->rxBa.htCapa);
		printk("rxBa.tidNum                 : %d\n", gSta->rxBa.tidNum);
		printk("rxBa.policyBM               : %d\n", gSta->rxBa.policyBM);
		printk("ctrl_port_state             : %d\n", gSta->ctrl_port_state);

		wl_kfree(temp);
	} else if (!memcmp(strArray_p->strArray[0], "smac-tbl-bss", 12)) {
		SMAC_BSS_ENTRY_st *pBss;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 index = atohex2(strArray_p->strArray[2]);
		UINT32 *temp;
		int i;

		temp = wl_kmalloc(sizeof(SMAC_BSS_ENTRY_st) + 4, GFP_KERNEL);

		if (temp == NULL) {
			printk("Failed to alloc SMAC_BSS_ENTRY_st space size = %d\n", (int)sizeof(SMAC_BSS_ENTRY_st));
			goto out;
		}

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		if ((address > 0xC0000000) || (index > 0x1000)) {
			if (temp)
				wl_kfree(temp);

			netdev_alert(netdev, "invalid address %#08x or index %u\n", address, index);
			goto out;
		}

		pBss = (SMAC_BSS_ENTRY_st *) (address + priv->ioBase0);

		memcpy((void *)temp, (void *)&pBss[index], sizeof(SMAC_BSS_ENTRY_st));

		printk("\nBSS table = %d address = %p size=%d\n", index, &pBss[index], (int)sizeof(SMAC_BSS_ENTRY_st));

		for (i = 0; i < sizeof(SMAC_BSS_ENTRY_st) / 4; i++)
			temp[i] = ENDIAN_SWAP32(temp[i]);

		pBss = (SMAC_BSS_ENTRY_st *) temp;

		printk("macAddr             : %02x:%02x:%02x:%02x:%02x:%02x\n", pBss->macAddr[0], pBss->macAddr[1], pBss->macAddr[2],
		       pBss->macAddr[3], pBss->macAddr[4], pBss->macAddr[5]);
		printk("capaInfo            : 0x%04x\n", pBss->capaInfo);
		printk("bssBasicRate        : 0x%04x\n", pBss->bssBasicRate);
		printk("lowestRateMcs       : 0x%04x\n", pBss->lowestRateMcs);
		printk("ackTxTime           : %d\n", pBss->ackTxTime);
		printk("rtsThreshold        : %d\n", pBss->rtsThreshold);
		printk("shortRetryLimit     : %d\n", pBss->shortRetryLimit);
		printk("longRetryLimit      : %d\n", pBss->longRetryLimit);
		printk("ePifs               : 0x%02x - 0x%02x\n", pBss->ePifs[0], pBss->ePifs[1]);
		printk("sifs                : %d\n", pBss->sifs);
		printk("sigExtension        : %d\n", pBss->sigExtension);
		printk("SN                  : 0x%04x\n", pBss->SN);
		printk("timeStampDly        : 0x%08x\n", pBss->timeStampDly);
		printk("bcnTsf              : 0x%08x\n", pBss->bcnTsf);
		printk("bcnTsfMsb           : 0x%08x\n", pBss->bcnTsfMsb);
		printk("bcnInterval         : %d\n", pBss->bcnInterval);
		printk("bcnPifs             : %d\n", pBss->bcnPifs);
		printk("DSbit               : %d\n", pBss->DSbit);
		printk("bssIndex            : %d\n", pBss->bssIndex);
		printk("NonQosPeerCnt       : %d\n", pBss->NonQosPeerCnt);
		printk("qosMask             : 0x%x\n", pBss->qosMask);
		wl_kfree(temp);
	} else if (!memcmp(strArray_p->strArray[0], "smac-tbl-txq", 8)) {
		SMAC_TXQ_ENTRY_st *txqTbl;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 qid = atohex2(strArray_p->strArray[2]);
		UINT32 temp[sizeof(SMAC_TXQ_ENTRY_st) / 4];

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		txqTbl = (SMAC_TXQ_ENTRY_st *) (address + priv->ioBase0);
		txqTbl += qid;

		memcpy((void *)&temp, (void *)txqTbl, sizeof(temp));

		printk("\nSMAC txq table qid = %d   address = %p\n", qid, txqTbl);

		mwl_hex_dump((UINT8 *) & temp, sizeof(temp));

		txqTbl = (SMAC_TXQ_ENTRY_st *) temp;

		printk("\nqid     = %d\n", ENDIAN_SWAP16(txqTbl->qid));
		printk("next    = 0x%08x \n", ENDIAN_SWAP32(txqTbl->reserved[0]));
		printk("prev    = 0x%08x \n", ENDIAN_SWAP32(txqTbl->reserved[1]));

		printk("numMSDU = %d\n", ENDIAN_SWAP16(txqTbl->numMSDU));
		printk("numMPDU = %d\n", ENDIAN_SWAP16(txqTbl->numMPDU));
		printk("txqMark = %d\n", ENDIAN_SWAP16(txqTbl->txqMark));
		printk("\n\n");
	} else if (!memcmp(strArray_p->strArray[0], "limit-txq", 8)) {
		TXD_TXLIMIT_t *gTxdTxlimit;
		UINT32 address = atohex2(strArray_p->strArray[1]);
		UINT32 index = atohex2(strArray_p->strArray[2]);
		UINT32 temp[sizeof(TXD_TXLIMIT_t) / 4];
		int i;

		if (address >= DMEM_IN_FW_START_ADDR)
			address -= DMEM_IN_FW_START_ADDR;

		if ((address > 0xC0000000) || (index > 0x1000)) {
			netdev_alert(netdev, "invalid address %#08x or index %u\n", address, index);
			goto out;
		}

		gTxdTxlimit = (TXD_TXLIMIT_t *) (address + priv->ioBase0);

		memcpy((void *)&temp, (void *)&gTxdTxlimit[index], sizeof(temp));

		printk("txq limit table idx = %d - address = %p\n", index, &gTxdTxlimit[index]);

		for (i = 0; i < sizeof(temp) / 4; i++)
			temp[i] = ENDIAN_SWAP32(temp[i]);

		gTxdTxlimit = (TXD_TXLIMIT_t *) temp;

		printk("l0MinUnit    :: 0x%08x\n", gTxdTxlimit->l0MinUnit);
		printk("l0MinPkt     :: 0x%08x\n", gTxdTxlimit->l0MinPkt);
		printk("l0MaxUnit    :: 0x%08x\n", gTxdTxlimit->l0MaxUnit);
		printk("l0MaxPkt     :: 0x%08x\n", gTxdTxlimit->l0MaxPkt);
	} else if (!memcmp(strArray_p->strArray[0], "drv-defrag", 10)) {
		int i;

		printk("DRV::: cnt_defrag_drop = %d\n", wlexcept_p->cnt_defrag_drop);
		for (i = 0; i < sizeof(wlexcept_p->cnt_defrag_drop_x) / sizeof(wlexcept_p->cnt_defrag_drop_x[0]); i++) {
			printk("\t %d", wlexcept_p->cnt_defrag_drop_x[i]);
		}
		printk("\n");
	}
#if 0
	else if (!memcmp(strArray_p->strArray[0], "drv-test-defrag", 15)) {
		//WDS iwpriv wdev0ap0 setcmd "debug drv-test-defrag 1 2 3 0 1 00504302fe01"  <-self
		//AP  iwpriv wdev0ap0 setcmd "debug drv-test-defrag 1 2 3 0 1 7e50432233e4"  <-peer
		//STA iwpriv wdev0sta0 setcmd "debug drv-test-defrag 1 2 3 0 1 0050432233e4" <-peer             
		extern UINT32 wl_proc_mic_defrag(struct net_device *netdev,
						 struct except_cnt *wlexcept_p, wlrxdesc_t * pCurCfhul, struct sk_buff **pRxSkBuff);
		UINT32 frameType, euMode, fromDs, toDs, pktLen, dataLen, device;
		UINT8 cfhul[32] = { 0x30, 0x00, 0x00, 0x05, 0x14, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xfc, 0x89, 0x2b, 0xb3,
			0x80, 0xc0, 0x55, 0x5b, 0x00, 0x00, 0x00, 0x0a,
			0x88, 0x05, 0x00, 0x01, 0x00, 0x00, 0x63, 0x1e
		};
		UINT8 test_data[32] = { 0x00, 0x50, 0x43, 0x02, 0xfe, 0x01, 0x9c, 0xb7,
			0x0d, 0xef, 0xf5, 0x6f, 0x00, 0x12, 0x12, 0x34,
			0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90,
			0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56
		};
		UINT8 test_mgmt[150] = { 0xb0, 0x00, 0x9c, 0x00, 0x00, 0x50, 0x43, 0x02,
			0xfe, 0x01, 0x7e, 0x50, 0x43, 0x22, 0x33, 0xe4,
			0x00, 0x50, 0x43, 0x02, 0xfe, 0x01, 0x10, 0x00,
			0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
			0x78, 0x90, 0x12, 0x34,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
			0x00, 0x00, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x21, 0x39, 0xf2, 0x86,
			0x80, 0xe0, 0xbc, 0x5d, 0x00, 0x00, 0x00, 0x0a,
			0xb0, 0x00, 0x50, 0x00, 0x23, 0x03, 0x63, 0x1c,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x06, 0x00, 0x00, 0x10, 0xb0, 0x00, 0x9c, 0x00,
			0x00, 0x50, 0x43, 0x02, 0xfe, 0x01, 0x7e, 0x50,
			0x43, 0x22, 0x33, 0xe4, 0x00, 0x50, 0x43, 0x02,
			0xfe, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00
		};
		UINT8 *pTestData;
		struct net_device *locNetdev = netdev;
		wlrxdesc_t *pCfhul = (wlrxdesc_t *) & cfhul[0];
		IEEEtypes_FrameCtl_t *frame_ctlp = (IEEEtypes_FrameCtl_t *) & pCfhul->frame_ctrl;
		struct sk_buff *pRxSkBuff[4];
		UINT8 i = 0, mac[6];

		device = atohex2(strArray_p->strArray[1]);	//0: AP mode, 1: STA mode, 2: WDS mode                 
		frameType = atohex2(strArray_p->strArray[2]);
		euMode = atohex2(strArray_p->strArray[3]);
		fromDs = atohex2(strArray_p->strArray[4]);
		toDs = atohex2(strArray_p->strArray[5]);

		getMacFromString(mac, strArray_p->strArray[6]);

		printk("drv-test-defrag: mac = %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		frame_ctlp->FromDs = fromDs;
		frame_ctlp->ToDs = toDs;
		pCfhul->euMode = euMode;
		if (device == 2) {
			for (i = 0; i < MAX_WDS_PORT; i++) {
				if (memcmp(priv->vmacSta_p->wdsPort[i].netDevWds->dev_addr, mac, 6) == 0) {
					if (priv->vmacSta_p->wdsPort[i].active) {
						locNetdev = priv->vmacSta_p->wdsPort[i].netDevWds;
						break;
					}
				}
			}
		}
		if (frameType == IEEE_TYPE_MANAGEMENT) {
			frame_ctlp->Type = IEEE_TYPE_MANAGEMENT;
			pCfhul->hdr.seqNum = 0x0560;
			pCfhul->macHdrLen = 24 + SMAC_HDR_LENGTH_BEFORE_MAC_HDR;
			pCfhul->cfh_offset = 0x0050;
			pTestData = &test_mgmt[0];
			memcpy(&test_data[10], mac, sizeof(mac));
			pktLen = sizeof(test_mgmt);
			dataLen = 36;
		} else {
			frame_ctlp->Type = IEEE_TYPE_DATA;
			pCfhul->hdr.seqNum = 0x0780;
			pTestData = &test_data[0];
			memcpy(&test_data[6], mac, sizeof(mac));
			dataLen = pktLen = sizeof(test_data);
		}

		for (i = 0; i < 4; i++) {
			if (i < 3)
				frame_ctlp->MoreFrag = 1;
			else
				frame_ctlp->MoreFrag = 0;

			pRxSkBuff[i] = wl_alloc_skb(1024);

			if (pRxSkBuff[i]) {
				UINT8 *ptr = skb_tail_pointer(pRxSkBuff[i]);

				skb_put(pRxSkBuff[i], dataLen);
				memcpy(ptr, pTestData, pktLen);

				wl_proc_mic_defrag(locNetdev, wlexcept_p, pCfhul, &pRxSkBuff[i]);
			}
			pCfhul->hdr.seqNum++;
		}
	}
#endif
#ifdef RX_REPLAY_DETECTION
	else if (!memcmp(strArray_p->strArray[0], "pn-log", 6)) {
		UINT32 option = atohex2(strArray_p->strArray[1]);
		extern void dbg_replay_attack_print(void);

		if (option == 1) {
			extern UINT32 dbg_pn_goodCnt[8];
			extern UINT32 dbg_pn_badCnt[8];

			printk("Good[0] %d    %d    %d    %d\n", dbg_pn_goodCnt[0], dbg_pn_goodCnt[1], dbg_pn_goodCnt[2], dbg_pn_goodCnt[3]);
			printk("Good[4] %d    %d    %d    %d\n", dbg_pn_goodCnt[4], dbg_pn_goodCnt[5], dbg_pn_goodCnt[6], dbg_pn_goodCnt[7]);
			printk("Bad [0] %d    %d    %d    %d\n", dbg_pn_badCnt[0], dbg_pn_badCnt[1], dbg_pn_badCnt[2], dbg_pn_badCnt[3]);
			printk("Bad [4] %d    %d    %d    %d\n", dbg_pn_badCnt[4], dbg_pn_badCnt[5], dbg_pn_badCnt[6], dbg_pn_badCnt[7]);
		} else {
			dbg_replay_attack_print();
		}
	} else if (!memcmp(strArray_p->strArray[0], "drv-sta-pn", 10)) {
		UINT8 mac[6];
		extStaDb_StaInfo_t *pStaInfo;

		getMacFromString(mac, strArray_p->strArray[1]);

		pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) mac, STADB_DONT_UPDATE_AGINGTIME);

		if (pStaInfo) {
			printk("Bad PN Cnt:  ucast=%d, mcast=%d, mgmt=%d\n",
			       pStaInfo->pn->ucastBadCnt, pStaInfo->pn->mcastBadCnt, pStaInfo->pn->mgmtBadCnt);
		} else
			printk("Can't find STA DB for MAC=%s\n", strArray_p->strArray[1]);

	}
#endif
	else if ((!memcmp(strArray_p->strArray[0], "ccmp", 4)) || (!memcmp(strArray_p->strArray[0], "gcmp", 4))) {
		/* ccmp mac keyIndex keys */
		extern int wlFwSetSecurityKey(struct net_device *netdev, UINT16 action, UINT8 type,
					      UINT8 * pMacAddr, UINT8 keyIndex, UINT16 keyLen, UINT32 keyInfo, UINT8 * pKeyParam);
		extern void HexStringToHexDigi(char *outHexData, char *inHexString, UINT16 Len);

		//AES_TYPE_KEY param = {0};
		AES_TYPE_KEY param;
		UINT32 keyIndex = atohex2(strArray_p->strArray[2]);
		UINT32 keyLen;
		UINT32 keyType = KEY_TYPE_ID_CCMP;
		UINT8 mac[6];
		UINT32 keyInfo = ENCR_KEY_FLAG_PTK;

		memset(&param, 0, sizeof(AES_TYPE_KEY));
		keyLen = strlen(strArray_p->strArray[3]) / 2;

		if ((keyLen == 16) || (keyLen == 32)) {
			if (!memcmp(strArray_p->strArray[0], "gcmp", 4))
				keyType = KEY_TYPE_ID_GCMP;

			getMacFromString(mac, strArray_p->strArray[1]);
			HexStringToHexDigi(param.KeyMaterial, strArray_p->strArray[3], keyLen);

			wlFwSetSecurityKey(netdev, ACT_SET, keyType, mac, keyIndex, keyLen, keyInfo, (UINT8 *) & param);
		} else
			printk("Input error size keyLen=%d \n", keyLen);
	} else if (!memcmp(strArray_p->strArray[0], "tkip", 4)) {
		/* tkip mac keyIndex keys txmickey rxmickey */
		extern int wlFwSetSecurityKey(struct net_device *netdev, UINT16 action, UINT8 type,
					      UINT8 * pMacAddr, UINT8 keyIndex, UINT16 keyLen, UINT32 keyInfo, UINT8 * pKeyParam);
		extern void HexStringToHexDigi(char *outHexData, char *inHexString, UINT16 Len);

		TKIP_TYPE_KEY param;
		UINT32 keyIndex = atohex2(strArray_p->strArray[2]);
		UINT32 keyLen, txMicKeyLen, rxMicKeyLen;
		UINT8 mac[6];
		UINT32 keyInfo = ENCR_KEY_FLAG_PTK;

		memset(&param, 0, sizeof(TKIP_TYPE_KEY));
		keyLen = strlen(strArray_p->strArray[3]) / 2;
		txMicKeyLen = strlen(strArray_p->strArray[4]) / 2;
		rxMicKeyLen = strlen(strArray_p->strArray[5]) / 2;

		if ((keyLen == 16) && (txMicKeyLen == 8) && (rxMicKeyLen == 8)) {
			getMacFromString(mac, strArray_p->strArray[1]);
			HexStringToHexDigi(param.KeyMaterial, strArray_p->strArray[3], keyLen);
			HexStringToHexDigi(param.TxMicKey, strArray_p->strArray[4], txMicKeyLen);
			HexStringToHexDigi(param.RxMicKey, strArray_p->strArray[5], rxMicKeyLen);

			wlFwSetSecurityKey(netdev, ACT_SET, KEY_TYPE_ID_TKIP, &mac[0], keyIndex, keyLen, keyInfo, (UINT8 *) & param);
		} else
			printk("Input error size keyLen=%d txMicKeyLen=%d rxMicKeyLen=%d\n", keyLen, txMicKeyLen, rxMicKeyLen);
	} else if (!memcmp(strArray_p->strArray[0], "wep", 3)) {
		/* wep mac keyIndex keys */
		extern int wlFwSetSecurityKey(struct net_device *netdev, UINT16 action, UINT8 type,
					      UINT8 * pMacAddr, UINT8 keyIndex, UINT16 keyLen, UINT32 keyInfo, UINT8 * pKeyParam);
		extern void HexStringToHexDigi(char *outHexData, char *inHexString, UINT16 Len);

		WEP_TYPE_KEY param;
		UINT32 keyIndex = atohex2(strArray_p->strArray[2]);
		UINT32 keyLen;
		UINT8 mac[6];
		UINT32 keyInfo = ENCR_KEY_FLAG_PTK | ENCR_KEY_FLAG_WEP_TXKEY;

		memset(&param, 0, sizeof(WEP_TYPE_KEY));
		keyLen = strlen(strArray_p->strArray[3]) / 2;

		if ((keyLen == 5) || (keyLen == 13)) {
			getMacFromString(mac, strArray_p->strArray[1]);
			HexStringToHexDigi(param.KeyMaterial, strArray_p->strArray[3], keyLen);

			wlFwSetSecurityKey(netdev, ACT_SET, KEY_TYPE_ID_WEP, &mac[0], keyIndex, keyLen, keyInfo, (UINT8 *) & param);
		} else
			printk("Input error size keyLen=%d \n", keyLen);
	} else if (!memcmp(strArray_p->strArray[0], "wapi", 4)) {
		/* wapi mac keyIndex keys micKeys */
		extern int wlFwSetSecurityKey(struct net_device *netdev, UINT16 action, UINT8 type,
					      UINT8 * pMacAddr, UINT8 keyIndex, UINT16 keyLen, UINT32 keyInfo, UINT8 * pKeyParam);
		extern void HexStringToHexDigi(char *outHexData, char *inHexString, UINT16 Len);
		UINT8 pn[2][16] = { {0x37, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c},
		{0x37, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c}
		};

		WAPI_TYPE_KEY param;
		UINT32 pnIndex = atohex2(strArray_p->strArray[2]);
		UINT32 keyIndex = atohex2(strArray_p->strArray[3]);
		UINT32 keyLen, micKeyLen;
		UINT8 mac[8];
		UINT32 keyInfo = ENCR_KEY_FLAG_PTK;

		memset(&param, 0, sizeof(WAPI_TYPE_KEY));
		keyLen = strlen(strArray_p->strArray[4]) / 2;
		micKeyLen = strlen(strArray_p->strArray[5]) / 2;

		if ((keyLen == 16) && (micKeyLen == 16)) {
			getMacFromString(mac, strArray_p->strArray[1]);

			HexStringToHexDigi(param.KeyMaterial, strArray_p->strArray[4], keyLen);
			HexStringToHexDigi(param.MicKeyMaterial, strArray_p->strArray[5], micKeyLen);

			if (pnIndex > 1)
				pnIndex = 0;

			if (pnIndex)
				keyInfo = ENCR_KEY_FLAG_GTK_TX_KEY;

			memcpy(param.PN, pn[pnIndex], 16);

			printk("wapi::: mac=%s keyIndex=%d keyLen=%d micKeyLen=%d\n", strArray_p->strArray[1], keyIndex, keyLen, micKeyLen);
			mwl_hex_dump((UINT8 *) & param, sizeof(param));
			wlFwSetSecurityKey(netdev, ACT_SET, KEY_TYPE_ID_WAPI, mac, keyIndex, keyLen, keyInfo, (UINT8 *) & param);
		} else
			printk("Input error size keyLen=%d micKeyLen=%d\n", keyLen, micKeyLen);
	} else if (!memcmp(strArray_p->strArray[0], "addsta", 6)) {
		UINT32 Aid = atohex2(strArray_p->strArray[2]);
		UINT32 StnId = atohex2(strArray_p->strArray[3]);
		UINT32 mac[6];
		UINT32 wdsFlag = 0, qosFlag = 0, Qosinfo = 0;
		PeerInfo_t PeerInfo;
		setStaPeerInfo(&PeerInfo, atohex2(strArray_p->strArray[4]), atohex2(strArray_p->strArray[5]), atohex2(strArray_p->strArray[6]),
			       atohex2(strArray_p->strArray[7]));
		getMacFromString((unsigned char *)mac, strArray_p->strArray[1]);
		if (argc > 8)
			wdsFlag = atohex2(strArray_p->strArray[8]);
		if (argc > 9) {
			qosFlag = atohex2(strArray_p->strArray[9]);
			Qosinfo = 0xf;
		}

		wlFwSetNewStn(netdev, (u_int8_t *) mac, Aid, StnId, StaInfoDbActionAddEntry, &PeerInfo, Qosinfo, qosFlag, wdsFlag);	//add new station    
		wl_set_da(mac);
	} else if (!memcmp(strArray_p->strArray[0], "delsta", 6)) {
		UINT32 mac[6];
		getMacFromString((unsigned char *)mac, strArray_p->strArray[1]);
		wlFwSetNewStn(netdev, (u_int8_t *) mac, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);	//del station first
	} else if (!memcmp(strArray_p->strArray[0], "addba", 5)) {
		//UINT8 amsdu_bitmap = 0;
		UINT16 staid;
		UINT8 mac[6];
		UINT8 tid;
		UINT8 density;
		UINT8 vhtfactor;
		UINT8 direction;
		UINT8 ba4roam = false;
		MIB_802DOT11 *smib = vmacSta_p->ShadowMib802dot11;
		UINT8 amsdu_bitmap = *(smib->mib_amsdutx);
		getMacFromString((unsigned char *)mac, strArray_p->strArray[1]);
		staid = atohex2(strArray_p->strArray[3]);
		tid = atohex2(strArray_p->strArray[2]);
		density = atohex2(strArray_p->strArray[4]);
		vhtfactor = atohex2(strArray_p->strArray[5]);	//default to 64k
		if (argc > 6)
			direction = atohex2(strArray_p->strArray[6]);
		else
			direction = 1;	// to be compatible with previous version
		if (argc > 7)
			ba4roam = atohex2(strArray_p->strArray[7]);
		else
			ba4roam = 0;
		printk("%s(), ba4roam: %u\n", __func__, ba4roam);
		priv->is_ba4roam = ba4roam;
		wlFwCreateBAStream(netdev, 64, 64, (u_int8_t *) mac, 10, tid, amsdu_bitmap, direction, density, NULL, 0, vhtfactor, 0, staid);
		priv->is_ba4roam = 0;
		//wlFwCreateBAStream(vmacSta_p->dev, pAddBaReqFrm->ParamSet.BufSize, pAddBaReqFrm->ParamSet.BufSize , (u_int8_t *)&(MgmtMsg_p->Hdr.SrcAddr), 10, pAddBaReqFrm->ParamSet.tid, amsdu_bitmap,  1,pStaInfo->HtElem.MacHTParamInfo,(u_int8_t *)&(MgmtMsg_p->Hdr.DestAddr), pAddBaReqFrm->SeqControl.Starting_Seq_No,pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent,0);

	} else if (!memcmp(strArray_p->strArray[0], "setedcaparam", 12)) {
		UINT32 indx = atohex2(strArray_p->strArray[1]);
		UINT32 cwmin = atohex2(strArray_p->strArray[2]);
		UINT32 cwmax = atohex2(strArray_p->strArray[3]);
		UINT32 aifsn = atohex2(strArray_p->strArray[4]);
		UINT32 txopLimit = atohex2(strArray_p->strArray[5]);
		wlFwSetEdcaParam(netdev, indx, cwmin, cwmax, aifsn, txopLimit);
		//wlFwSetEdcaParam(struct net_device *netdev, u_int8_t Indx, u_int32_t CWmin, u_int32_t CWmax, u_int8_t AIFSN,  u_int16_t TXOPLimit)
	} else if (!memcmp(strArray_p->strArray[0], "setmaxdelay", 11)) {
		UINT32 ac = atohex2(strArray_p->strArray[1]);
		UINT32 maxdelay = atohex2(strArray_p->strArray[2]);
		wlFwAcMaxTolerableDelay(netdev, 0, ac, &maxdelay);
	} else if (!memcmp(strArray_p->strArray[0], "getmaxdelay", 11)) {
		UINT32 ac = atohex2(strArray_p->strArray[1]);
		UINT32 maxdelay;
		wlFwAcMaxTolerableDelay(netdev, 1, ac, &maxdelay);
		printk("max delay for ac %x is %x\n", ac, maxdelay);
	}
#else
	if (!memcmp(strArray_p->strArray[0], "coredumpmode", 12)) {
		printk("coredump triggered\n");
		wlFwDiagMode(netdev, 1);
	} else if (!memcmp(strArray_p->strArray[0], "coredump", 8)) {
		coredump_cmd_t *core_dump = NULL;
		coredump_t cd;
		char *buff = NULL;
		UINT32 i, offset;
		printk("coredump started\n");
		do {
			core_dump = (coredump_cmd_t *) wl_kmalloc(sizeof(coredump_cmd_t), GFP_ATOMIC);
			if (!core_dump) {
				printk("Error[%s:%d]: Allocating F/W Core Dump Memory \n", __func__, __LINE__);
				break;
			}

			buff = (char *)wl_kmalloc(MAX_CORE_DUMP_BUFFER, GFP_ATOMIC);
			if (!buff) {
				printk("Error[%s:%d]: Allocating F/W Buffer for Core Dump \n", __func__, __LINE__);
				break;
			}
			memset((char *)buff, 0, MAX_CORE_DUMP_BUFFER);
			/*Get Core Dump From F/W */
			core_dump->context = 0;
			core_dump->flags = 0;
			core_dump->sizeB = 0;
			if (wlFwGetCoreDump(netdev, core_dump, buff) == FAIL) {
				printk("Error[%s:%d]: Failed to get Core Dump \n", __func__, __LINE__);
				break;
			}
			memcpy(&cd, buff, sizeof(coredump_t));
			printk("Major Version : %d\n", cd.version_major);
			printk("Minor Version : %d\n", cd.version_minor);
			printk("Patch Version : %d\n", cd.version_patch);
			printk("Num of Regions: %d\n", cd.num_regions);
			printk("Num of Symbols: %d\n", cd.num_symbols);
			for (i = 0; i < cd.num_regions; i++) {
				printk("\ncd.region[%d].address=%x, cd.region[%d].length=%x\n", i, cd.region[i].address, i, cd.region[i].length);

				for (offset = 0; offset < cd.region[i].length; offset += MAX_CORE_DUMP_BUFFER) {
					core_dump->context = (i << 28) | offset;
					core_dump->flags = 0;
					core_dump->sizeB = 0;
					printk("%s", ".");
					if (wlFwGetCoreDump(netdev, core_dump, buff) == FAIL) {
						printk("Error[%s:%d]: Failed to get Core Dump offset %x\n", __func__, __LINE__, offset);
						break;
					}
					core_dump_file(buff, MAX_CORE_DUMP_BUFFER, cd.region[i].address,
						       cd.region[i].address + offset, offset, cd.region[i].length, atohex2(strArray_p->strArray[1]));
				}
			}
		} while (0);
		if (buff)
			wl_kfree(buff);

		if (core_dump)
			wl_kfree(core_dump);
	}
#endif				/* SOC_W906X */
	else if (!memcmp(strArray_p->strArray[0], "injectrx", 8)) {
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
		struct sk_buff *skb;
		UINT8 *frm;
		UINT32 frameSize = 0;
		UINT32 subtype = 0xffffffff;
		UINT32 len = 0;
		UINT32 wep = atohex2(strArray_p->strArray[2]);
		UINT32 adjustheader = wep ? 8 : 0;
		UINT32 adjusttail = wep ? 8 : 0;
		char SrcAddr[6];
		//char DstAddr[6];
		//char Bssid[6];
		//memcpy(DstAddr, vmacSta_p->macStaAddr, 6);
		//memcpy(Bssid, vmacSta_p->macStaAddr, 6);
		extStaDb_list(vmacSta_p, SrcAddr, 1);
		if (!memcmp(strArray_p->strArray[1], "auth", 4)) {
			subtype = IEEE_MSG_AUTHENTICATE;
			len = authAndAssoc[0].len;
			memcpy(DebugData, authAndAssoc[0].data, len);
		} else if (!memcmp(strArray_p->strArray[1], "assoc", 5)) {
			subtype = IEEE_MSG_ASSOCIATE_RQST;
			len = authAndAssoc[1].len;
			memcpy(DebugData, authAndAssoc[1].data, len);
		} else if (!memcmp(strArray_p->strArray[1], "deauth", 6)) {
			subtype = IEEE_MSG_DEAUTHENTICATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		} else if (!memcmp(strArray_p->strArray[1], "deassoc", 7)) {
			subtype = IEEE_MSG_DISASSOCIATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		}
		if ((skb = ieee80211_getmgtframe(&frm, 1000)) != NULL) {
			MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) skb->data;
			MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
			MgmtMsg_p->Hdr.FrmCtl.Subtype = subtype;
			MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
			MgmtMsg_p->Hdr.FrmCtl.Wep = wep;
			MgmtMsg_p->Hdr.Duration = 300;
			memcpy(&MgmtMsg_p->Hdr.DestAddr, vmacSta_p->macStaAddr, sizeof(IEEEtypes_MacAddr_t));
			memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr, sizeof(IEEEtypes_MacAddr_t));
			memcpy(&MgmtMsg_p->Hdr.BssId, vmacSta_p->macStaAddr, sizeof(IEEEtypes_MacAddr_t));
			memcpy(&MgmtMsg_p->Body.data[adjustheader], DebugData, len);
			frameSize = sizeof(IEEEtypes_MgmtHdr3_t) + len + adjustheader + adjusttail;
			skb_trim(skb, frameSize);
			MgmtMsg_p->Hdr.FrmBodyLen = frameSize;
			wlDumpData((unsigned char *)__FUNCTION__, MgmtMsg_p, MgmtMsg_p->Hdr.FrmBodyLen + 2);
			evtDot11MgtMsg(vmacSta_p, (UINT8 *) MgmtMsg_p, skb, 0);
		}

	} else if (!memcmp(strArray_p->strArray[0], "tx", 2)) {
		UINT32 subtype = 0;
		UINT32 len = 0;
		char Addr[64] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		char SrcAddr[6];
		char Bssid[6];
		char DebugData[64];
		UINT8 sent = 0;
		UINT32 flag = atohex2(strArray_p->strArray[2]);
		UINT8 brcst = atohex2(strArray_p->strArray[3]);
		UINT8 plain = atohex2(strArray_p->strArray[4]);
		memcpy(SrcAddr, vmacSta_p->macStaAddr, 6);
		memcpy(Bssid, vmacSta_p->macStaAddr, 6);
		if (!brcst) {
			/* allow using the 5th argument to specify unicast MAC */
			if ((strArray_p->strArray[5][0] == 0) || (getMacFromString(Addr, strArray_p->strArray[5]) == 0))
				extStaDb_list(vmacSta_p, Addr, 1);

			printk("\n ### Unicast MAC (%02x:%02x:%02x:%02x:%02x:%02x)\n", Addr[0], Addr[1], Addr[2], Addr[3], Addr[4], Addr[5]);

			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
				memcpy(Bssid, Addr, 6);

			if (Addr[0] & 0x1) {
				printk("conflicted mac address and brcst flag setting!!!\n");
				goto out;
			}
		} else {
			flag = 0;
			if (plain == 1)	//plain
				;	//DebugBitSet(1);
			else if (plain == 2)	//wrong key
				;	//DebugBitSet(0);
		}
		if (!memcmp(strArray_p->strArray[1], "deauthall", 9)) {
			extStaDb_RemoveAllStns(vmacSta_p, IEEEtypes_REASON_DEAUTH_LEAVING);
		} else if (!memcmp(strArray_p->strArray[1], "deauth", 6)) {
			subtype = IEEE_MSG_DEAUTHENTICATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		} else if (!memcmp(strArray_p->strArray[1], "deassoc", 7)) {
			subtype = IEEE_MSG_DISASSOCIATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		} else if (!memcmp(strArray_p->strArray[1], "saquery", 7)) {
			subtype = IEEE_MSG_QOS_ACTION | flag;
#ifdef CONFIG_IEEE80211W
			macMgmtMlme_SAQuery(vmacSta_p, (IEEEtypes_MacAddr_t *) Addr, (IEEEtypes_MacAddr_t *) SrcAddr, subtype);
#endif
			sent = 1;
		}

		if (sent == 0) {
			subtype |= flag;
			DebugSendMgtMsg(netdev, subtype, (IEEEtypes_MacAddr_t *) Addr, (IEEEtypes_MacAddr_t *) SrcAddr,
					(IEEEtypes_MacAddr_t *) Bssid, DebugData, len);

			// for deauth or disassoc
			if (plain == 0) {	//correctly protected deauthentication 
				if (brcst)
					extStaDb_RemoveAllStns(vmacSta_p, IEEEtypes_REASON_DEAUTH_LEAVING);
				else
					extStaDb_DelSta(vmacSta_p, (IEEEtypes_MacAddr_t *) Addr, STADB_DONT_UPDATE_AGINGTIME);
			}
		}
	} else if (!memcmp(strArray_p->strArray[0], "tcpack", 6)) {
		debug_tcpack = atohex2(strArray_p->strArray[1]);
		myprint "debug_tcpack %s\n", debug_tcpack ? "enabled" : "disabled");
	}
#ifdef CAP_MAX_RATE
	else if (!memcmp(strArray_p->strArray[0], "mcscap", 6)) {
		MCSCapEnable = atohex2(strArray_p->strArray[1]);

		myprint "MCS cap %s. To enable, mcscap 1 <mcs_value>\n", MCSCapEnable ? "enabled" : "disabled");
		if (MCSCapEnable) {
			if (atohex2(strArray_p->strArray[2]) > 23) {
				myprint "Pls specify MCS <= 23\n");
				MCSCapEnable = 0;
				myprint "MCS cap disabled\n");
			} else {
				MCSCap = atohex2(strArray_p->strArray[2]);
				myprint "Rate capped at MCS%d\n", MCSCap);
			}
		}
	}
#endif
	else if (!memcmp(strArray_p->strArray[0], "vhtcap", 6)) {

		vht_cap = atohex2(strArray_p->strArray[1]);
		SupportedRxVhtMcsSet = atohex2(strArray_p->strArray[2]);
		mib_StaCfg->SupportedTxVhtMcsSet = atohex2(strArray_p->strArray[3]);
		myprint "vht_cap=%x  SupportedRxVhtMcsSet=%x  SupportedTxVhtMcsSet=%x\n",
		    (unsigned int)vht_cap, (unsigned int)SupportedRxVhtMcsSet, (unsigned int)mib_StaCfg->SupportedTxVhtMcsSet);

	} else if (!memcmp(strArray_p->strArray[0], "vhtopt", 6)) {
		if (argc > 4) {
			basic_vht_mcs = atohex2(strArray_p->strArray[4]);
		}
		if (argc > 3) {
			center_freq1 = atohex2(strArray_p->strArray[3]);
		}
		if (argc > 2) {
			center_freq0 = atohex2(strArray_p->strArray[2]);
		}
		if (argc > 1) {
			ch_width = atohex2(strArray_p->strArray[1]);
		}
		myprint "ch_width=%d  center_freq0=%d  center_freq1=%d  basic_vht_mcs=%x\n",
		    (int)ch_width, (int)center_freq0, (int)center_freq1, (unsigned int)basic_vht_mcs);
	} else if (!memcmp(strArray_p->strArray[0], "read", 4)) {
		UINT32 *location;
		location = (UINT32 *) atohex2(strArray_p->strArray[1]);
		if (location)
			myprint "location 0x%p = %x\n", location, *(volatile UINT32 *)location);
	} else if (!memcmp(strArray_p->strArray[0], "write", 5)) {
		UINT32 *location, val;
		location = (UINT32 *) atohex2(strArray_p->strArray[1]);
		val = atohex2(strArray_p->strArray[2]);
		if (location) {
			*location = val;
			myprint "write %x to location 0x%p\n", val, location);
		}
	} else if (!memcmp(strArray_p->strArray[0], "dump", 4)) {
		struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
		{
			unsigned int i, val, offset, length;

			if (!memcmp(strArray_p->strArray[1], "mm", 2)) {
				offset = atohex2(strArray_p->strArray[2]);
				if (offset > 0xffff) {
					goto out;
				}

				length = atohex2(strArray_p->strArray[3]);
				if (!length)
					length = 32;
				else
					length = (length < 32) ? length : 32;

				printk("dump mem\n");
				for (i = 0; i < length; i += 4) {
					volatile unsigned int val = 0;

					val = *(volatile unsigned int *)(priv->ioBase1 + offset + i);

					if (i % 8 == 0) {
						printk("\n%08x: ", (int)(0x80000000 + offset + i));
					}
					printk("  %08x", val);
				}
			} else if (!memcmp(strArray_p->strArray[1], "rf", 2)) {
				offset = atohex2(strArray_p->strArray[2]);
				length = atohex2(strArray_p->strArray[3]);
				if (!length)
					length = 32;
				else
					length = (length < 32) ? length : 32;

				printk("dump rf regs\n");
				for (i = 0; i < length; i++) {
					wlRegRF(netdev, 0, offset + i, &val);
					if (i % 8 == 0) {
						printk("\n%02x: ", (int)(offset + i));
					}
					printk("  %02x", (int)val);
				}
			} else if (!memcmp(strArray_p->strArray[1], "bb", 2)) {
				offset = atohex2(strArray_p->strArray[2]);
				length = atohex2(strArray_p->strArray[3]);
				if (!length)
					length = 32;
				else
					length = (length < 32) ? length : 32;

				printk("dump bb regs\n");
				for (i = 0; i < length; i++) {
					wlRegBB(netdev, 0, offset + i, &val);
					if (i % 8 == 0) {
						printk("\n%02x: ", (int)(offset + i));
					}
					printk("  %02x", (int)val);
				}
			}
		}
	} else if (!memcmp(strArray_p->strArray[0], "map", 3)) {
#ifdef SOC_W8964
#if 1
		extern void wlRxDescriptorDump(struct net_device *netdev);
		extern void wlTxDescriptorDump(struct net_device *netdev);
		wlRxDescriptorDump(netdev);
		wlTxDescriptorDump(netdev);
#else
		UINT8 mac[6];
		int param1, param2, set = 0;
		MacAddrString(strArray_p->strArray[1], mac);
		set = atohex2(strArray_p->strArray[2]);
		if (set) {
			param1 = atohex2(strArray_p->strArray[3]);
			param2 = atohex2(strArray_p->strArray[4]);
		}
#endif
#endif				/* SOC_W8964 */
	} else if (!memcmp(strArray_p->strArray[0], "dra", 3)) {
		UINT32 tbl = atohex2(strArray_p->strArray[2]);
		UINT32 type = atohex2(strArray_p->strArray[3]);
		UINT32 value_lo = atohex2(strArray_p->strArray[4]);
		UINT32 value_mi = atohex2(strArray_p->strArray[5]);
		UINT32 value_hi = atohex2(strArray_p->strArray[6]);
		UINT32 max_retry_range = atohex2(strArray_p->strArray[7]);
		UINT32 timer_mask = atohex2(strArray_p->strArray[8]);
		UINT32 dynamic_dra = atohex2(strArray_p->strArray[9]);
		UINT32 noisy_rxload_thresh = atohex2(strArray_p->strArray[10]);
		UINT32 tlvData[32];
		u8 *str_type[] = {
		"SU", "160M_MCS8", "MU_2User", "MU_3User", "MU_4User"};
		u8 *str_tbl[] = {
		"MIN_TX_PKT_THRES", "PER_THRES", "TIME_CONSTANT_FOR_RATE_INCREASE"};
		extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type, UINT16 len, UINT8 * tlvData, char *string_buff);

		tlvData[0] = tbl;
		tlvData[1] = type;

		if ((tbl > 2) || (type > 4)) {
			printk("Invalid input\n");
			goto out;
		}

		if (dynamic_dra > 1)
			dynamic_dra = 1;

		if (noisy_rxload_thresh > 100)
			noisy_rxload_thresh = 100;

		if (!memcmp(strArray_p->strArray[1], "get", 3)) {
			printk("Get DRA table %s type %s\n", str_tbl[tbl], str_type[type]);
			wlFwGetTLVSet(netdev, 0, 20, 8, (UINT8 *) tlvData, NULL);
		} else if (!memcmp(strArray_p->strArray[1], "set", 3)) {
			tlvData[2] = value_lo;
			tlvData[3] = value_mi;
			tlvData[4] = value_hi;
			tlvData[5] = max_retry_range;
			tlvData[6] = timer_mask;
			tlvData[7] = dynamic_dra;
			tlvData[8] = noisy_rxload_thresh;
			printk("Set DRA table %s type %s LOW: %d MID: %d HI: %d\n", str_tbl[tbl], str_type[type], value_lo, value_mi, value_hi);
			printk("Set DRA retryRange %d timer_mask 0x%x dynamic_dra %d noisy_rxload_thresh %d\n", max_retry_range, timer_mask,
			       dynamic_dra, noisy_rxload_thresh);
			wlFwGetTLVSet(netdev, 1, 20, 36, (UINT8 *) tlvData, NULL);
		} else
			printk("operation %s not supported\n", strArray_p->strArray[1]);
	} else if (!memcmp(strArray_p->strArray[0], "eapol_m1_delay", strlen("eapol_m1_delay"))) {
		if (!memcmp(strArray_p->strArray[1], "get", strlen("get")))
			printk("the debug_m1_delay is %lu\n", debug_m1_delay);
		else if (!memcmp(strArray_p->strArray[1], "set", strlen("set")))
			debug_m1_delay = simple_strtoul(strArray_p->strArray[2], NULL, 10);
		else
			printk("operation %s not supported\n", strArray_p->strArray[1]);
	} else if (!memcmp(strArray_p->strArray[0], "acs_weight", strlen("acs_weight"))) {
		if (!memcmp(strArray_p->strArray[1], "get", strlen("get"))) {
			printk("acs_ch_load_weight: %d\n", vmacSta_p->acs_ch_load_weight);
			printk("acs_ch_nf_weight: %d\n", vmacSta_p->acs_ch_nf_weight);
			printk("acs_ch_distance_weight: %d\n", vmacSta_p->acs_ch_distance_weight);
			printk("acs_bss_distance_weight: %d\n", vmacSta_p->acs_bss_distance_weight);
			printk("acs_bss_num_weight: %d\n", vmacSta_p->acs_bss_num_weight);
			printk("acs_rssi_weight: %d\n", vmacSta_p->acs_rssi_weight);
			printk("acs_adjacent_bss_weight: %d\n", vmacSta_p->acs_adjacent_bss_weight);
			printk("acs_adjacent_bss_weight_plus: %d\n", vmacSta_p->acs_adjacent_bss_weight_plus);
		} else if (!memcmp(strArray_p->strArray[1], "set", strlen("set"))) {
			vmacSta_p->acs_ch_load_weight = simple_strtoul(strArray_p->strArray[2], NULL, 10);
			vmacSta_p->acs_ch_nf_weight = simple_strtoul(strArray_p->strArray[3], NULL, 10);
			vmacSta_p->acs_ch_distance_weight = simple_strtoul(strArray_p->strArray[4], NULL, 10);
			vmacSta_p->acs_bss_distance_weight = simple_strtoul(strArray_p->strArray[5], NULL, 10);
			vmacSta_p->acs_bss_num_weight = simple_strtoul(strArray_p->strArray[6], NULL, 10);
			vmacSta_p->acs_rssi_weight = simple_strtoul(strArray_p->strArray[7], NULL, 10);
			vmacSta_p->acs_adjacent_bss_weight = simple_strtoul(strArray_p->strArray[8], NULL, 10);
			vmacSta_p->acs_adjacent_bss_weight_plus = simple_strtoul(strArray_p->strArray[9], NULL, 10);
		} else
			printk("operation %s not supported\n", strArray_p->strArray[1]);
	} else if (!memcmp(strArray_p->strArray[0], "help", 4)) {
		myprint "read <location>\nwrite <location> <value>\ndump <start location> <length>\nfunc <arg#> <param ...>\n");
	} else {
		myprint "No Valid Commands found\n");
	}
 out:
	myfree(strArray_p);
	return (0);
}

inline int wl_check_dbg_classlevel(UINT32 classlevel) {
	UINT32 level = classlevel & 0x0000ffff;
	UINT32 class = classlevel & 0xffff0000;
	int rc = 0;

	if ((class & dbg_class) != class)
		rc = -1;

	else if ((level & dbg_level) != level) {
		if (class != DBG_CLASS_PANIC && class != DBG_CLASS_ERROR)
			rc = -1;
	}

	return rc;
}

void _wlPrint(UINT32 classlevel, const char *func, const char *format, va_list args) {
	unsigned char debugString[1020] = "";	//Reduced from 1024 to 1020 to prevent frame size > 1024bytes warning during compilation
	UINT32 class = classlevel & 0xffff0000;
	u_int32_t str_len = 0;

	if (format != NULL) {
		vsnprintf(debugString, sizeof(debugString), format, args);
	}

	switch (class) {
	case DBG_CLASS_ENTER:
		myprint "Enter %s() ...\n", func);
		break;
	case DBG_CLASS_EXIT:
		myprint "... Exit %s()\n", func);
		break;
	case DBG_CLASS_WARNING:
		myprint "WARNING:");
		break;
	case DBG_CLASS_ERROR:
		myprint "ERROR:");
		break;
	case DBG_CLASS_PANIC:
		myprint "PANIC:");
		break;
	default:
		break;
	}

	str_len = (strlen(debugString) < sizeof(debugString)) ? strlen(debugString) : sizeof(debugString);

	if (str_len > 0) {
		if (debugString[str_len - 1] == '\n')
			debugString[str_len - 1] = '\0';
		myprint "%s(): %s\n", func, debugString);
	}
}

void wlPrint(UINT32 classlevel, const char *func, const char *format, ...) {
	va_list args;

	if (!wl_check_dbg_classlevel(classlevel)) {
		va_start(args, format);
		_wlPrint(classlevel, func, format, args);
		va_end(args);
	}
}

void mwl_hex_dump_to_sysfs(const void *buf, size_t len, char *sysfs_buff) {
	const char *level = "";
	const char *prefix_str = "";
	int prefix_type = DUMP_PREFIX_OFFSET;
	int rowsize = 16;
	int groupsize = 1;
	bool ascii = false;
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 1];

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize, linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			Sysfs_Printk("%s%s%p: %s\n", level, prefix_str, ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			Sysfs_Printk("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
			break;
		default:
			Sysfs_Printk("%s%s%s\n", level, prefix_str, linebuf);
			break;
		}
	}
	return;
}

void mwl_hex_dump(const void *buf, size_t len) {
	const char *level = "";
	const char *prefix_str = "";
	int prefix_type = DUMP_PREFIX_OFFSET;
	int rowsize = 16;
	int groupsize = 1;
	bool ascii = false;
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 1];

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize, linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			pr_info("%s%s%p: %s\n", level, prefix_str, ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			pr_info("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
			break;
		default:
			pr_info("%s%s%s\n", level, prefix_str, linebuf);
			break;
		}
	}
	return;
}

void wlHexDump(UINT32 classlevel, const void *data, size_t len) {
	if (!wl_check_dbg_classlevel(classlevel))
		mwl_hex_dump(data, len);
}

void _wlPrintData(const char *func, const void *data, int len, const char *format, va_list args) {
	unsigned char debugString[992] = "";	//Reduced from 1024 to 992 to prevent frame size > 1024bytes warning during compilation
	unsigned char debugData[16] = "";
	unsigned char *memptr = (unsigned char *)data;
	int currByte = 0;
	int numBytes = 0;
	int offset = 0;
	u_int32_t str_len = 0;

	if (format != NULL) {
		vsnprintf(debugString, sizeof(debugString), format, args);
	}

	str_len = (strlen(debugString) < sizeof(debugString)) ? strlen(debugString) : sizeof(debugString);
	if (str_len > 0) {
		if (debugString[str_len - 1] == '\n')
			debugString[str_len - 1] = '\0';
		myprint "%s() %s\n", func, debugString);
	}

	for (currByte = 0; currByte < len; currByte = currByte + 8) {
		if ((currByte + 8) < len) {
			myprint "%s() 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
			    func,
			    *(memptr + currByte + 0),
			    *(memptr + currByte + 1),
			    *(memptr + currByte + 2),
			    *(memptr + currByte + 3),
			    *(memptr + currByte + 4), *(memptr + currByte + 5), *(memptr + currByte + 6), *(memptr + currByte + 7));
		} else {
			numBytes = len - currByte;
			offset = currByte;
			sprintf(debugString, "%s() ", func);
			for (currByte = 0; currByte < numBytes; currByte++) {
				sprintf(debugData, "0x%02x ", *(memptr + offset + currByte));
				strcat(debugString, debugData);
			}
			myprint "%s\n", debugString);
			break;
		}
	}
}

void wlPrintData(UINT32 classlevel, const char *func, const void *data, int len, const char *format, ...) {
	va_list args;

	if (!wl_check_dbg_classlevel(classlevel)) {
		va_start(args, format);
		_wlPrintData(func, data, len, format, args);
		va_end(args);
	}
}

#ifdef QUEUE_STATS
#ifdef QUEUE_STATS_LATENCY
static int initCnt[4] = {
0, 0, 0, 0};

UINT8 rx_initCnt[3] = {
0, 0, 0};

rx_stats_q_stats_t rx_QueueStats;

void wldbgRecPktTime(u_int32_t pkt_tm, u_int32_t cur_tm, int ac_id) {
	u_int32_t delta;

	if ((pkt_tm > 0) && (cur_tm > pkt_tm)) {
		delta = cur_tm - pkt_tm;
		if (wldbgTxACxPktStats[ac_id].TxPktLatency_Max == 0) {
			wldbgTxACxPktStats[ac_id].TxPktLatency_Min = delta;
			wldbgTxACxPktStats[ac_id].TxPktLatency_Max = delta;
			wldbgTxACxPktStats[ac_id].TxPktLatency_Mean = (delta >> 3);
		} else {
			if (delta > wldbgTxACxPktStats[ac_id].TxPktLatency_Max) {
				wldbgTxACxPktStats[ac_id].TxPktLatency_Max = delta;
			} else if (delta < wldbgTxACxPktStats[ac_id].TxPktLatency_Min) {
				wldbgTxACxPktStats[ac_id].TxPktLatency_Min = delta;
			}
			if (initCnt[ac_id] < 7) {
				wldbgTxACxPktStats[ac_id].TxPktLatency_Mean += (delta >> 3);
				initCnt[ac_id]++;
			} else {
				wldbgTxACxPktStats[ac_id].TxPktLatency_Mean = ((wldbgTxACxPktStats[ac_id].TxPktLatency_Mean * 5 + delta * 3) >> 3);
			}
		}
	}
}

/******************************************************************************
*
* Name: wldbgRecRxMinMaxMean
*
* Description:
*    basic routine to classify the value x to be min or max the basic_stats_t 
*    variable, then calculate the mean.
*
* Conditions For Use:
*    The stats module has been initialized.
*
* Arguments:
*    Arg1 (i  ): x - the value
*                pStats  - pointer to a basic_stats_t variable
*                n    - pointer to control counter
* Return Value:
*    None.
*
* Notes:
*    None.
*
*****************************************************************************/
void wldbgRecRxMinMaxMean(UINT32 x, basic_stats_t * pStats, UINT8 * n) {
	if (pStats->Max == 0) {
		pStats->Min = x;
		pStats->Max = x;
		pStats->Mean = (x >> 3);
		(*n) = 1;

	} else {
		if (x > pStats->Max) {
			pStats->Max = x;
		} else if (x < pStats->Min) {
			pStats->Min = x;
		}
		if ((*n) < 8) {
			pStats->Mean += (x >> 3);
			(*n) += 1;
		} else {
			pStats->Mean = ((pStats->Mean * 5 + x * 3) >> 3);
		}
	}
}
#endif

void wldbgPrintPktStats(int option) {
	int i;
	char *ac[4] = {
	"BK", "BE", "VI", "VO"};

#ifdef QUEUE_STATS_LATENCY
	if (option == 1) {
		printk("\nDRV Packet Latency (microsecond)\n");
		printk("ACQ\t DRV_Min\t   DRV_Max\t   DRV_Mean\n");
		for (i = 0; i < 4; i++) {
			if (wldbgTxACxPktStats[i].TxPktLatency_Max) {
				printk("%s    %10u\t%10u\t%10u\n", ac[i],
				       wldbgTxACxPktStats[i].TxPktLatency_Min,
				       wldbgTxACxPktStats[i].TxPktLatency_Max, wldbgTxACxPktStats[i].TxPktLatency_Mean);
			}
		}
	} else if (option == 2) {
		printk("\nRX: Fw-To-Drv DMA Packet Latency (microsecond)\n");
		printk("FWtoDRV_Min\t   FWtoDRV_Max\t   FWtoDRV_Mean\n");
		printk("%10u\t%10u\t%10u\n",
		       rx_QueueStats.Latency.FwToDrvLatency.Min, rx_QueueStats.Latency.FwToDrvLatency.Max, rx_QueueStats.Latency.FwToDrvLatency.Mean);
		printk("\nRX: Drv Packet Latency (microsecond)\n");
		printk("DRV_Min\t   DRV_Max\t   DRV_Mean\n");
		printk("%10u\t%10u\t%10u\n",
		       rx_QueueStats.Latency.DrvLatency.Min, rx_QueueStats.Latency.DrvLatency.Max, rx_QueueStats.Latency.DrvLatency.Mean);
		printk("\nRX: Total Packet Latency (microsecond)\n");
		printk("Total_Min\t   Total_Max\t   Total_Mean\n");
		printk("%10u\t%10u\t%10u\n",
		       rx_QueueStats.Latency.TotalLatency.Min, rx_QueueStats.Latency.TotalLatency.Max, rx_QueueStats.Latency.TotalLatency.Mean);
	}
#endif
#ifdef QUEUE_STATS_CNT_HIST
	if (option == 0) {
		printk("---------------------\n");
		printk("DRV Packet Statistics\n");
		printk("---------------------");
		printk("\nTx Packet Counters\n");
		printk("AC\t   TxOk\t\t    DfsDrop\t  IffDrop\t TxQDrop\t ErrorCnt\tMaxQueueDepth\n");
		for (i = 0; i < 4; i++) {
			if (wldbgTxACxPktStats[i].TxOkCnt) {
				printk("%s    %10u\t%10u\t%10u\t%10u\t%10u\t%10u\n", ac[i],
				       wldbgTxACxPktStats[i].TxOkCnt,
				       wldbgTxACxPktStats[i].TxDfsDropCnt,
				       wldbgTxACxPktStats[i].TxIffDropCnt,
				       wldbgTxACxPktStats[i].TxTxqDropCnt, wldbgTxACxPktStats[i].TxErrorCnt, wldbgTxACxPktStats[i].txQdepth);
			}
		}
		printk("\nTCP/UDP Counters\n");
		printk("AC \t   TCP\t\t     UDP\t\t ICMP\t\t UDP_SRC_PORT=%d\n", dbgUdpSrcVal1);
		for (i = 0; i < 4; i++) {
			if (wldbgTxACxPktStats[i].TxOkCnt) {
				printk("%s    %10u\t%10u\t    %10u\t\t%10u\n", ac[i],
				       wldbgTxACxPktStats[i].TCPCnt,
				       wldbgTxACxPktStats[i].UDPCnt, wldbgTxACxPktStats[i].ICMPCnt, wldbgTxACxPktStats[i].SMARTBITS_UDPCnt);
			}
		}

		printk("\nDrv Per STA Counters\n");
		printk("MAC address\t\tTx_Pkt_In\tTx_Pkt_Out\t   TxQDrop\n");
		for (i = 0; i < 4; i++) {
			if (txPktStats_sta[i].valid) {
				printk("%02x:%02x:%02x:%02x:%02x:%02x\t",
				       txPktStats_sta[i].addr[0],
				       txPktStats_sta[i].addr[1],
				       txPktStats_sta[i].addr[2], txPktStats_sta[i].addr[3], txPktStats_sta[i].addr[4], txPktStats_sta[i].addr[5]);
				printk("%10u\t%10u\t%10u\n", txPktStats_sta[i].TxEnQCnt, txPktStats_sta[i].TxOkCnt, txPktStats_sta[i].TxqDropCnt);
			}
		}
	}
#endif
}

#ifdef QUEUE_STATS_CNT_HIST
void wldbgRecPerStatxPktStats(UINT8 * addr, UINT8 type) {
	int l;
	for (l = 0; l < 4; l++) {
		if (txPktStats_sta[l].valid) {
			if (*(UINT32 *) (&addr[2]) == *(UINT32 *) (&txPktStats_sta[l].addr[2])) {
				if (type == QS_TYPE_TX_EN_Q_CNT) {
					txPktStats_sta[l].TxEnQCnt++;
				} else if (type == QS_TYPE_TX_OK_CNT_CNT) {
					txPktStats_sta[l].TxOkCnt++;
				} else if (type == QS_TYPE_TX_Q_DROPE_CNT) {
					txPktStats_sta[l].TxqDropCnt++;
				}
				break;
			}
		}
	}
}
#endif

void wldbgResetQueueStats(void) {
#ifdef QUEUE_STATS_CNT_HIST
	int i;

	for (i = 0; i < 4; i++) {
		txPktStats_sta[i].TxOkCnt = 0;
		txPktStats_sta[i].TxEnQCnt = 0;
		rxPktStats_sta[i].Rx80211InputCnt = 0;
		rxPktStats_sta[i].RxfwdCnt = 0;
		rxPktStats_sta[i].RxRecvPollCnt = 0;
	}
#endif
	memset(wldbgTxACxPktStats, 0x0, (sizeof(wldbgPktStats_t) * 4));
	dbgUdpSrcVal1 = dbgUdpSrcVal;
#ifdef QUEUE_STATS_LATENCY
	memset(initCnt, 0x0, (sizeof(int) * 4));
	memset(rx_initCnt, 0x0, (sizeof(int) * 3));
	memset(&rx_QueueStats, 0x0, (sizeof(rx_stats_q_stats_t)));

#endif
}

#endif
void wlDumpData(unsigned char *mark, const void *data, int len) {
	unsigned char *debugString;
	unsigned char debugData[16] = "";
	unsigned char *memptr = (unsigned char *)data;
	int currByte = 0;
	int numBytes = 0;
	int offset = 0;

	if ((debugString = wl_kmalloc_autogfp(len + 1024)) == NULL)
		return;

	printk("%s: \n", mark);
	for (currByte = 0; currByte < len; currByte = currByte + 8) {
		if ((currByte + 8) < len) {
			printk("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
			       *(memptr + currByte + 0),
			       *(memptr + currByte + 1),
			       *(memptr + currByte + 2),
			       *(memptr + currByte + 3),
			       *(memptr + currByte + 4), *(memptr + currByte + 5), *(memptr + currByte + 6), *(memptr + currByte + 7));
		} else {
			numBytes = len - currByte;
			offset = currByte;
			for (currByte = 0; currByte < numBytes; currByte++) {
				sprintf(debugData, "0x%02x ", *(memptr + offset + currByte));
				strcat(debugString, debugData);
			}
			printk("%s\n\n", debugString);
			break;
		}
	}
	wl_kfree(debugString);
}

#ifdef SOC_W906X
int disableSMACRx(struct net_device *netdev) {
	int rc = 0;
	unsigned int reg, val;

	unsigned int *addr_val = wl_kmalloc_autogfp(64 * sizeof(unsigned int));
	if (!addr_val)
		return -EFAULT;

	memset(addr_val, 0, 64 * sizeof(unsigned int));

	reg = 0x90010000;
	val = 0;
	addr_val[0] = val;

	wlFwGetAddrValue(netdev, reg, 4, addr_val, 1);

	wl_kfree(addr_val);
	return rc;
}

int disableSMACTx(struct net_device *netdev) {
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	*(volatile unsigned int *)(wlpptr->ioBase0 + 0x14) = 0xffffffff;

	return 0;
}

void triggerCoredump(struct net_device *netdev) {
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	//Auto enable HM to log sma status/registers dump to dumpwdevx_sts_xxx
	if (wlpd_p->smon.active == 0) {
		printk("Auto Enable HM to collect mac register info:\n");
		wldbgCoreMonitor(netdev, WLMON_DEFAULT_ENABLE, WLMON_DEFAULT_HMMASK, SMAC_STATUS_FORMAT_RAW);
		msleep(6000);
	}

	wlFwDiagMode(netdev, 1);
}

void dbg_coredump(struct net_device *netdev) {
	extern unsigned int dbg_invalid_skb;

	// Disable SMAC TX/RX and trigger coredump:
	if (dbg_invalid_skb & dbg_ivalskb_coredump) {
		WLDBG_ERROR(DBG_LEVEL_0, "dbgskb: stop all skb tx/rx and trigger coredump!\n");
		disableSMACTx(netdev);
		disableSMACRx(netdev);
		triggerCoredump(netdev);
	}
}

/** private functions **/
static void setStaPeerInfo(PeerInfo_t * pPeerInfo, UINT8 ApMode, UINT8 nss, UINT8 bw, UINT8 gi) {
	UINT8 amsdu_bitmap;
	memset((void *)pPeerInfo, 0, sizeof(PeerInfo_t));

	switch (ApMode) {
	case AP_MODE_N_ONLY:
	case AP_MODE_BandN:
	case AP_MODE_GandN:
	case AP_MODE_BandGandN:
	case AP_MODE_AandN:
	case AP_MODE_11AC:
	case AP_MODE_11AX:
	case AP_MODE_2_4GHZ_11AC_MIXED:
	case AP_MODE_2_4GHZ_11AX_MIXED:
	case AP_MODE_2_4GHZ_Nand11AX:
	case AP_MODE_5GHZ_11AC_ONLY:
	case AP_MODE_5GHZ_11AX_ONLY:
	case AP_MODE_5GHZ_Nand11AC:
	case AP_MODE_5GHZ_ACand11AX:
	case AP_MODE_5GHZ_NandACand11AX:
		WLDBG_INFO(DBG_LEVEL_6, "WDS Port N Mode \n");

		if (bw != CH_20_MHz_WIDTH)
			pPeerInfo->HTCapabilitiesInfo.SupChanWidth = 1;
		else
			pPeerInfo->HTCapabilitiesInfo.SupChanWidth = 0;
		if (gi != 0) {
			pPeerInfo->HTCapabilitiesInfo.SGI20MHz = (gi == 2) ? 0 : 1;
			pPeerInfo->HTCapabilitiesInfo.SGI40MHz = (gi == 2) ? 0 : 1;
		} else {
			pPeerInfo->HTCapabilitiesInfo.SGI20MHz = 1;
			pPeerInfo->HTCapabilitiesInfo.SGI40MHz = 1;
		}
		pPeerInfo->HTCapabilitiesInfo.AdvCoding = 1;
		pPeerInfo->HTCapabilitiesInfo.MIMOPwSave = 0x3;

		//pPeerInfo->MacHTParamInfo     = *(wlpptr->vmacSta_p->Mib802dot11->mib_ampdu_factor)
		//    |((*(wlpptr->vmacSta_p->Mib802dot11->mib_ampdu_density))<<2);

		pPeerInfo->HTRateBitMap = ENDIAN_SWAP32((0xff | (0xff << 8) | (0xff << 16) | (0xff << 24)));
		if (1) {
			//amsdu_bitmap = (*(wlpptr->vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK);
			//if(amsdu_bitmap == WL_MODE_AMSDU_TX_11K)    
			amsdu_bitmap = WL_MODE_AMSDU_TX_11K;
			if (ApMode & AP_MODE_11AC) {
				if (nss == 3) {
					pPeerInfo->vht_MaxRxMcs = 0xffea;
				} else if (nss == 1) {
					pPeerInfo->vht_MaxRxMcs = 0xfffe;
				} else {
					pPeerInfo->vht_MaxRxMcs = 0xfffa;
				}

				if (bw == CH_160_MHz_WIDTH) {
					pPeerInfo->vht_RxChannelWidth = 3;
					vht_cap |= (1 << 2);	//set bit2 for 160Mhz support

					//If LGI
					if (gi == 2)
						vht_cap &= ~(1 << 6);
					else
						vht_cap |= (1 << 6);	//set bit6 for 160 or 80+80MHz SGI support
				} else {
					pPeerInfo->vht_RxChannelWidth = 2;
					vht_cap &= ~(1 << 2);

					if (gi == 2)
						vht_cap &= ~(1 << 5);
					else
						vht_cap |= (1 << 5);	//set bit5 for 80MHz SGI support
				}

				pPeerInfo->vht_cap = vht_cap;

				// Also need to update vhtCap.cap in StaIno which is needed for fw to set ampdu length
				//memcpy((UINT8 *)&pStaInfo->vhtCap.cap, (UINT8 *)&vht_cap, sizeof(IEEEtypes_VHT_Cap_Info_t));
			}
		}

		break;
	case AP_MODE_A_ONLY:
		pPeerInfo->CapInfo.APSD = 0;
		pPeerInfo->CapInfo.BlckAck = 0;
		pPeerInfo->CapInfo.CfPollable = 0;
		pPeerInfo->CapInfo.CfPollRqst = 0;
		pPeerInfo->CapInfo.ChanAgility = 0;
		pPeerInfo->CapInfo.DsssOfdm = 0;
		pPeerInfo->CapInfo.Ess = 1;
		pPeerInfo->CapInfo.Ibss = 0;
		pPeerInfo->CapInfo.Pbcc = 0;
		pPeerInfo->CapInfo.Privacy = 0;
		pPeerInfo->CapInfo.ShortPreamble = 1;
		pPeerInfo->CapInfo.ShortSlotTime = 1;
		pPeerInfo->LegacyRateBitMap = ENDIAN_SWAP32(0x00001FE0);	// Set for A rates.
		pPeerInfo->MrvlSta = 0;
		break;
	case AP_MODE_B_ONLY:
		pPeerInfo->CapInfo.APSD = 0;
		pPeerInfo->CapInfo.BlckAck = 0;
		pPeerInfo->CapInfo.CfPollable = 0;
		pPeerInfo->CapInfo.CfPollRqst = 0;
		pPeerInfo->CapInfo.ChanAgility = 0;
		pPeerInfo->CapInfo.DsssOfdm = 0;
		pPeerInfo->CapInfo.Ess = 1;
		pPeerInfo->CapInfo.Ibss = 0;
		pPeerInfo->CapInfo.Pbcc = 0;
		pPeerInfo->CapInfo.Privacy = 0;
		pPeerInfo->CapInfo.ShortPreamble = 1;
		pPeerInfo->CapInfo.ShortSlotTime = 1;
		pPeerInfo->LegacyRateBitMap = ENDIAN_SWAP32(0x0000000F);	// Set for b rates.
		pPeerInfo->MrvlSta = 0;
		break;
	default:		// case AP_MODE_G_ONLY:
		// case AP_MODE_MIXED:
		pPeerInfo->CapInfo.APSD = 0;
		pPeerInfo->CapInfo.BlckAck = 0;
		pPeerInfo->CapInfo.CfPollable = 0;
		pPeerInfo->CapInfo.CfPollRqst = 0;
		pPeerInfo->CapInfo.ChanAgility = 0;
		pPeerInfo->CapInfo.DsssOfdm = 0;
		pPeerInfo->CapInfo.Ess = 1;
		pPeerInfo->CapInfo.Ibss = 0;
		pPeerInfo->CapInfo.Pbcc = 0;
		pPeerInfo->CapInfo.Privacy = 0;
		pPeerInfo->CapInfo.ShortPreamble = 1;
		pPeerInfo->CapInfo.ShortSlotTime = 1;
		pPeerInfo->LegacyRateBitMap = ENDIAN_SWAP32(0x00001FFF);	// Set for g rates.
		pPeerInfo->MrvlSta = 0;
		break;

	}
}

//enable/disable background Core monitor.
void wldbgCoreMonitor(struct net_device *netdev, UINT32 enable, UINT32 bitmap, UINT32 format) {
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	int rc;

	//set bitmap of monitoring events
	wlpd_p->smon.ActiveBitmap = bitmap;

	//set smac status dump format
	wlpd_p->smon.smacStatusFormat = format;

	//enable active flag that start monitoring on this device.
	if (enable && !wlpd_p->smon.active) {
		printk("register %s core monitor\n", wlpd_p->rootdev->name);
		rc = register_wlmon_notifier(wlpd_p);
		if (rc == 0)
			wlpd_p->smon.active = 1;
	} else if (!enable && wlpd_p->smon.active) {
		printk("un-register %s core monitor\n", wlpd_p->rootdev->name);
		rc = unregister_wlmon_notifier(wlpd_p);
		if (rc == 0)
			wlpd_p->smon.active = 0;
	}

}

int wldbgCoreDump(struct notifier_block *nb, unsigned long action, void *data) {
	struct net_device *netdev = (struct net_device *)data;

	coredump_cmd_t *core_dump = NULL;
	coredump_t *pcd = NULL;
	char *buff = NULL;
	int i, offset;
	UINT32 time = 0;
	char fname[16] = {
	0};

	if (action) {
		//issue diagmode cmd to make sure PFW already being coredumpmode.
		printk("issue PFW CORE_DUMP_DIAG_MODE cmd..\n");
		wlFwDiagMode(netdev, 1);
		return 0;
	}

	do {
		pcd = (coredump_t *) wl_kmalloc(sizeof(coredump_t), GFP_ATOMIC);
		if (!pcd) {
			printk("Error[%s:%d]: Allocating Core Dump Memory \n", __func__, __LINE__);
			break;
		}

		core_dump = (coredump_cmd_t *) wl_kmalloc(sizeof(coredump_cmd_t), GFP_ATOMIC);
		if (!core_dump) {
			printk("Error[%s:%d]: Allocating F/W Core Dump Memory \n", __func__, __LINE__);
			break;
		}

		buff = (char *)wl_kmalloc(MAX_CORE_DUMP_BUFFER, GFP_ATOMIC);
		if (!buff) {
			printk("Error[%s:%d]: Allocating F/W Buffer for Core Dump \n", __func__, __LINE__);
			break;
		}
		memset((char *)buff, 0, MAX_CORE_DUMP_BUFFER);
		/*Get Core Dump From F/W */
		core_dump->context = 0;
		core_dump->flags = 0;
		core_dump->sizeB = 0;
		if (wlFwGetCoreDump(netdev, core_dump, buff) == FAIL) {
			break;
		}

		time = (UINT32) xxGetTimeStamp();	//use last word partial fileanme
		sprintf(fname, "%08x", time);

		memcpy(pcd, buff, sizeof(coredump_t));
		for (i = 0; i < pcd->num_regions; i++) {
			for (offset = 0; offset < pcd->region[i].length; offset += MAX_CORE_DUMP_BUFFER) {
				core_dump->context = (i << 27) | offset;
				core_dump->flags = 0;
				core_dump->sizeB = 0;
				if (wlFwGetCoreDump(netdev, core_dump, buff) == FAIL)
					break;
				core_dump_file(buff, MAX_CORE_DUMP_BUFFER, fname, i, pcd->region[i].address + offset, offset);
			}
		}
	} while (0);

	if (buff)
		wl_kfree(buff);

	if (core_dump)
		wl_kfree(core_dump);

	if (pcd)
		wl_kfree(pcd);

	return 0;

}
#endif				/* SOC_W906X */
