/*
*                Copyright 2005, Marvell Semiconductor, Inc.
* This code contains confidential information of Marvell Semiconductor, Inc.
* No rights are granted herein under any patent, mask work right or copyright
* of Marvell or any third party.
* Marvell reserves the right at its sole discretion to request that this code
* be immediately returned to Marvell. This code is provided "as is".
* Marvell makes no warranties, express, implied or otherwise, regarding its
* accuracy, completeness or performance.
*/

#ifndef AP8X_DESC_H_
#define AP8X_DESC_H_

#include <linux/if_ether.h>   
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#define roundup_MRVL(x, y)   ((((x)+((y)-1))/(y))*(y))

#define SOFT_STAT_STALE                               0x80

#define EAGLE_RXD_CTRL_DRIVER_OWN                     0x00
#define EAGLE_RXD_CTRL_OS_OWN                         0x04
#define EAGLE_RXD_CTRL_DMA_OWN                        0x80

#define EAGLE_RXD_STATUS_IDLE                         0x00
#define EAGLE_RXD_STATUS_OK                           0x01
#define EAGLE_RXD_STATUS_MULTICAST_RX                 0x02
#define EAGLE_RXD_STATUS_BROADCAST_RX                 0x04
#define EAGLE_RXD_STATUS_FRAGMENT_RX                  0x08

#define EAGLE_TXD_STATUS_IDLE                   0x00000000
#define EAGLE_TXD_STATUS_USED                   0x00000001 
#define EAGLE_TXD_STATUS_OK                     0x00000001
#define EAGLE_TXD_STATUS_OK_RETRY               0x00000002
#define EAGLE_TXD_STATUS_OK_MORE_RETRY          0x00000004
#define EAGLE_TXD_STATUS_MULTICAST_TX           0x00000008
#define EAGLE_TXD_STATUS_BROADCAST_TX           0x00000010
#define EAGLE_TXD_STATUS_FAILED_LINK_ERROR      0x00000020
#define EAGLE_TXD_STATUS_FAILED_EXCEED_LIMIT    0x00000040
#define EAGLE_TXD_STATUS_FAILED_AGING           0x00000080
#define EAGLE_TXD_STATUS_FW_OWNED               0x80000000

#define EAGLE_TXD_XMITCTRL_USE_RATEINFO         0x1
#define EAGLE_TXD_XMITCTRL_DISABLE_AMPDU        0x2
#define EAGLE_TXD_XMITCTRL_ENABLE_AMPDU         0x4
#define EAGLE_TXD_XMITCTRL_USE_MC_RATE          0x8     // Use multicast data rate

#define MRVL_PCI_DMA_SIGNATURE			0xCAFEEFAC

#ifdef SOC_W8764
typedef struct wlRateInfo_t
{
#ifdef MV_CPU_LE
	u_int32_t		Format:		1;	//0 = Legacy format, 1 = Hi-throughput format
	u_int32_t		ShortGI:	1;	//0 = Use standard guard interval,1 = Use short guard interval
	u_int32_t		Bandwidth:	1;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel
	u_int32_t		RateIDMCS:	7;	//= RateID[3:0]; Legacy format,= MCS[5:0]; HT format
	u_int32_t		AdvCoding:	1;	//AdvCoding 0 = No AdvCoding,1 = LDPC,2 = RS,3 = Reserved
	u_int32_t		AntSelect:	2;	//Bitmap to select one of the transmit antennae
	u_int32_t		ActSubChan:	2;   	//Active subchannel for 40 MHz mode 00:lower, 01= upper, 10= both on lower and upper
	u_int32_t  	Preambletype:1;  	//Preambletype 0= Long, 1= Short;
	u_int32_t 	pid:4; 				// Power ID
	u_int32_t 	ant2: 1; 			// bit 2 of antenna selection field 
	u_int32_t 	ant3: 1;
	u_int32_t 	bf: 1; 				// 0: beam forming off; 1: beam forming on
	u_int32_t 	gf:1; 				// 0: green field off; 1, green field on
	u_int32_t 	count:4;
	u_int32_t 	rsvd2:3;
	u_int32_t 	drop:1;
#else
	union {
	u_int32_t u32_data;
	struct {
	u_int32_t		drop:		1;
	u_int32_t		rsvd2:		3;
	u_int32_t		count:		4;
	u_int32_t 	gf:			1; 				
	u_int32_t 	bf: 			1; 				
	u_int32_t 	ant3: 		1;
	u_int32_t 	ant2: 		1; 			
	u_int32_t 	pid:			4; 				
	u_int32_t 	Preambletype:	1;
	u_int32_t 	ActSubChan:	2; 
	u_int32_t 	AntSelect: 	2; 
	u_int32_t 	AdvCoding: 	1; 
	u_int32_t 	RateIDMCS: 	7;
	u_int32_t 	Bandwidth: 	1; 
	u_int32_t 	ShortGI:		1; 
	u_int32_t 	Format: 		1; 	
	};	
	};
#endif
}__attribute__ ((packed)) wlRateInfo_t;
#else
typedef struct wlRateInfo_t
{
#ifdef MV_CPU_LE
	u_int16_t	Format:		1	;	//0 = Legacy format, 1 = Hi-throughput format
	u_int16_t	ShortGI:	1	;	//0 = Use standard guard interval,1 = Use short guard interval
	u_int16_t	Bandwidth:	1	;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel
	u_int16_t	RateIDMCS:	6	;	//= RateID[3:0]; Legacy format,= MCS[5:0]; HT format
	u_int16_t	AdvCoding:	2	;	//AdvCoding 0 = No AdvCoding,1 = LDPC,2 = RS,3 = Reserved
	u_int16_t	AntSelect:	2	;	//Bitmap to select one of the transmit antennae
	u_int16_t	ActSubChan:	2;   //Active subchannel for 40 MHz mode 00:lower, 01= upper, 10= both on lower and upper
	u_int16_t  	Preambletype:1;  //Preambletype 0= Long, 1= Short;
#else
	union {
	u_int16_t u16_data;
	struct {
	u_int16_t  Preambletype:1;  
	u_int16_t	ActSubChan:	 2;   
	u_int16_t	AntSelect:	 2;	
	u_int16_t	AdvCoding:	 2;
	u_int16_t	RateIDMCS:	 6;	
	u_int16_t	Bandwidth:	 1;	
	u_int16_t	ShortGI:	 1;	
	u_int16_t	Format:		 1;	
	};
	};	
#endif
}__attribute__ ((packed)) wlRateInfo_t;
#endif

struct rateinfo_t {
#ifdef MV_CPU_LE
	u_int16_t format:3;
	u_int16_t nss:2;
	u_int16_t bw:2;
	u_int16_t gi:1;
	u_int16_t rt:8; 
#else
	u_int16_t gi:1;
	u_int16_t bw:2;
	u_int16_t nss:2;
	u_int16_t format:3;
	u_int16_t rt:8; 
#endif
}__attribute__ ((packed));


typedef struct _wltxdesc_t /*__attribute__ ((packed))*/ wltxdesc_t;
struct _wltxdesc_t {
	u_int8_t         DataRate;
	u_int8_t         TxPriority;
	u_int16_t        QosCtrl;
	u_int32_t        PktPtr;
	u_int16_t        PktLen;
#ifdef ZERO_COPY
	u_int16_t     multiframes;
	u_int32_t   PktPtrArray[5];
	u_int16_t   PktLenArray[5];
#endif
	u_int8_t         DestAddr[6];
	u_int32_t        pPhysNext;
	u_int32_t        SapPktInfo;
	wlRateInfo_t 	RateInfo;
#if 1
	u_int8_t            type;
	u_int8_t    xmitcontrol;  //bit 0: use rateinfo, bit 1: disable ampdu
	u_int8_t  PacketInfo;
	u_int8_t  PacketID;
#else
	u_int16_t		type;
#endif
#ifdef TCP_ACK_ENHANCEMENT
	u_int32_t		tcpack_sn;
	u_int32_t		tcpack_src_dst;
#endif
    /* end TCP ACK Enh */

	struct sk_buff  *pSkBuff;
	wltxdesc_t    *pNext;
	u_int32_t  Retries;
	u_int16_t PacketLength;
	u_int16_t PacketRateInfo;

	u_int8_t		*staInfo;
#ifdef ZERO_COPY
	struct sk_buff  *pSkBuffArray[5];
#endif
    u_int32_t        Status;
#ifdef QUEUE_STATS_LATENCY
    u_int32_t        TimeStamp1;
    u_int32_t        TimeStamp2;
#endif
} __attribute__ ((packed));

typedef struct HwRssiInfo_t
{
	u_int32_t Rssi_a:   8;
	u_int32_t Rssi_b:   8;
	u_int32_t Rssi_c:   8;
#ifdef SOC_W8764
	u_int32_t Rssi_d:   8;
#else
	u_int32_t Reserved: 8;
#endif
}__attribute__ ((packed)) HwRssiInfo_t1;

typedef struct HwNoiseFloorInfo_t
{
	u_int32_t NoiseFloor_a: 8;
	u_int32_t NoiseFloor_b: 8;
	u_int32_t NoiseFloor_c: 8;
#ifdef SOC_W8764
	u_int32_t NoiseFloor_d: 8;
#else
	u_int32_t Reserved:     8;
#endif
}__attribute__ ((packed)) HwNoiseFloorInfo_t;

#ifdef SOC_W8363
typedef struct _wlrxdesc_t /*__attribute__ ((packed))*/ wlrxdesc_t;
struct _wlrxdesc_t {
	u_int8_t         RxControl;      /* the control element of the desc    */
	u_int8_t         RSSI;           /* received signal strengt indication */
	u_int8_t         Status;         /* status field containing USED bit   */
	u_int8_t         Channel;        /* channel this pkt was received on   */
	u_int16_t        PktLen;         /* total length of received data      */
	u_int8_t         SQ2;            /* unused at the moment               */
	u_int8_t         Rate;           /* received data rate                 */
	u_int32_t        pPhysBuffData;  /* physical address of payload data   */
	u_int32_t        pPhysNext;      /* physical address of next RX desc   */ 
	u_int16_t        QosCtrl;        /* received QosCtrl field variable    */
	u_int16_t        HtSig2;       /* like name states                   */
	struct HwRssiInfo_t HwRssiInfo;
	struct HwNoiseFloorInfo_t HwNoiseFloorInfo ;
	u_int8_t  NoiseFloor;
	struct sk_buff  *pSkBuff;        /* associated sk_buff for Linux       */
	void            *pBuffData;      /* virtual address of payload data    */ 
	wlrxdesc_t    *pNext;          /* virtual address of next RX desc    */
} __attribute__ ((packed));
#else

typedef struct _wlrxdesc_t /*__attribute__ ((packed))*/ wlrxdesc_t;
struct _wlrxdesc_t {
	u_int16_t        PktLen;         /* total length of received data      */
	u_int16_t		 rxrate;		

	u_int32_t        pPhysBuffData;  /* physical address of payload data   */
	u_int32_t        pPhysNext;      /* physical address of next RX desc   */ 
	u_int16_t        QosCtrl;        /* received QosCtrl field variable    */
	u_int16_t        HtSig2;       /* like name states                   */
#ifdef QUEUE_STATS_LATENCY
	u_int32_t  TimeStamp1;			/*Used for Total latency calculation from fw start to drv end*/
	u_int32_t  TimeStamp2;			/*Used for latency calculation as pkt moves from one section to another*/
#endif
	struct HwRssiInfo_t HwRssiInfo;
	struct HwNoiseFloorInfo_t HwNoiseFloorInfo ;
	u_int8_t  NoiseFloor;
#ifdef QUEUE_STATS_CNT_HIST
        u_int8_t qsRxTag;
        u_int8_t reserved[2];
#else
	u_int8_t reserved[3];
#endif	
	u_int8_t         RSSI;           /* received signal strengt indication */
	u_int8_t         Status;         /* status field containing USED bit   */
	u_int8_t         Channel;        /* channel this pkt was received on   */
	u_int8_t         RxControl;      /* the control element of the desc    */
	//above are 32bits aligned and is same as FW, RxControl put at end for sync	
	struct sk_buff  *pSkBuff;        /* associated sk_buff for Linux       */
	void            *pBuffData;      /* virtual address of payload data    */ 
	wlrxdesc_t    *pNext;          /* virtual address of next RX desc    */
} __attribute__ ((packed));
#endif
extern int wlTxRingAlloc(struct net_device *netdev);
extern int wlRxRingAlloc(struct net_device *netdev);
extern int wlTxRingInit(struct net_device *netdev);
extern int wlRxRingInit(struct net_device *netdev);
extern void wlTxRingFree(struct net_device *netdev);
extern void wlRxRingFree(struct net_device *netdev);
extern void wlTxRingCleanup(struct net_device *netdev);
extern void wlRxRingCleanup(struct net_device *netdev);

#ifndef HISTOGRAM_FROM_RATE_FEEDBACK


#define RATE_DECODE(x) \
{   \
	struct rateinfo_t* rp = (struct rateinfo_t*)&x; \
    int _11G_rate[14]={1,2,5,11,22,6,9,12,18,24,36,48,54,72};  \
    char *bwStr[3] = {"ht20","ht40", "ht80"};   \
    char *sgiStr[2] = {"lgi","sgi"};   \
	switch(rp->format) \
    {					\
        case 0:						\
        /*11a*/						 \
		case 1:						  \
		/*11b*/						   \
	        printk("legacy rate %2dMbps\n",_11G_rate[rp->rt]); \
        break;               									 \
        case 2:													  \
        /*11n*/									   \
			printk("11n %4s_%3s_MCS%2d\n", bwStr[rp->bw],sgiStr[rp->gi], rp->rt);\
            break;																		  \
        case 4:																			   \
        /*11ac*/														\
       		printk("11ac %4s_%3s_%1dSS_MCS%2d\n",bwStr[rp->bw],sgiStr[rp->gi], rp->nss+1, rp->rt); \
            break;		  \
        default:		   \
			printk("invalid format %x\n", x);     \
        	break;									   \
    }													\
} \

#else

#define RATE_DECODE(x, y) \
{   \
	struct rateinfo_t* rp = (struct rateinfo_t*)&x; \
    int _11G_rate[14]={1,2,5,11,22,6,9,12,18,24,36,48,54,72};  \
    char *bwStr[3] = {"ht20","ht40", "ht80"};   \
    char *sgiStr[2] = {"lgi","sgi"};   \
	switch(rp->format) \
    {					\
        case 0:						\
        /*11a*/						 \
		case 1:						  \
		/*11b*/						   \
			y.LegacyRates[rp->rt]++;	\
	        /*printk("legacy rate %2dMbps\n",_11G_rate[rp->rt]);*/ \
        break;               									 \
        case 2:													  \
        /*11n*/									   \
			y.HtRates[rp->bw][rp->gi][rp->rt]++;	\
			/*printk("11n %4s_%3s_MCS%2d\n", bwStr[rp->bw],sgiStr[rp->gi], rp->rt);*/\
            break;																		  \
        case 4:																			   \
        /*11ac*/														\
			y.VHtRates[rp->nss][rp->bw][rp->gi][rp->rt]++;	\
       		/*printk("11ac %4s_%3s_%1dSS_MCS%2d\n",bwStr[rp->bw],sgiStr[rp->gi], rp->nss+1, rp->rt);*/ \
            break;		  \
        default:		   \
			/*printk("invalid format 0x%x 0x%x\n", rp->format, x);*/     \
        	break;									   \
    }													\
} \


#endif

#endif /* AP8X_DESC_H_ */

