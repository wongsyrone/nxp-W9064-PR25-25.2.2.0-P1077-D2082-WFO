/** @file ap8xLnxRegs.h
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
#ifndef AP8X_REGS_H_
#define AP8X_REGS_H_

#define EAGLE_NDIS_MAJOR_VERSION 0x5

#ifdef MRVL_WINXP_NDIS51
#define EAGLE_NDIS_MINOR_VERSION 0x1
#else
#define EAGLE_NDIS_MINOR_VERSION 0x0
#endif

#define EAGLE_DRIVER_VERSION ((EAGLE_NDIS_MAJOR_VERSION * 0x100) + EAGLE_NDIS_MINOR_VERSION)

#ifdef SOC_W906X
#define MRVL_PCI_VENDOR_ID_Count            1
#else
#define MRVL_PCI_VENDOR_ID_Count            2
#endif /* SOC_W906X */
#define MRVL_PCI_VENDOR_ID                  0x11AB	// VID
#define MRVL_PCI_VENDOR_ID1                 0x11AB	// VID
#define MRVL_PCI_VENDOR_ID2                 0x1B4B	// VID
#define MRVL_8100_PCI_DEVICE_ID             0x2A02	// DID

#define MRVL_8100_PCI_REV_0                 0x00
#define MRVL_8100_PCI_REV_1                 0x01
#define MRVL_8100_PCI_REV_2                 0x02
#define MRVL_8100_PCI_REV_3                 0x03
#define MRVL_8100_PCI_REV_4                 0x04
#define MRVL_8100_PCI_REV_5                 0x05
#define MRVL_8100_PCI_REV_6                 0x06
#define MRVL_8100_PCI_REV_7                 0x07
#define MRVL_8100_PCI_REV_8                 0x08
#define MRVL_8100_PCI_REV_9                 0x09
#define MRVL_8100_PCI_REV_a                 0x0a
#define MRVL_8100_PCI_REV_b                 0x0b
#define MRVL_8100_PCI_REV_c                 0x0c
#define MRVL_8100_PCI_REV_d                 0x0d
#define MRVL_8100_PCI_REV_e                 0x0e
#define MRVL_8100_PCI_REV_f                 0x0f

#define MRVL_8100_PCI_VER_ID               0x00
#define MRVL_8100_CARDBUS_VER_ID           0x01
#define PCI_REG_SCRATCH0_REG      0x101C
#define PCI_REG_SCRATCH1_REG      0x1020
#define PCI_REG_SCRATCH2_REG      0x1024
#define PCI_REG_SCRATCH3_REG      0x1028
#define PCI_REG_SCRATCH4_REG      0x102c
#define PCI_REG_SCRATCH5_REG      0x1030
#define PCI_REG_SCRATCH6_REG      0x1034
#define PCI_REG_SCRATCH7_REG      0x1038
#define PCI_REG_SCRATCH8_REG      0x103c
#define PCI_REG_SCRATCH9_REG      0x1040
#define PCI_REG_SCRATCH10_REG     0x1044
#define PCI_REG_SCRATCH11_REG     0x1048
#define PCI_REG_SCRATCH12_REG     0x104c
#define PCI_REG_SCRATCH13_REG     0x1050
#define PCI_REG_SCRATCH14_REG     0x1054

#define PCI_REG_DOORBELL_ADDR		0x90000948
#define PCI_REG_HOST_ITR_ADDR		0x90001070
#define SC5_RX_MSIX_MASK                      0x000003FF
#define SC5_BUF_MSIX_MASK                     0x00003C00

#define SC5_EVENT_RADAR_DETECTED_AUX          BIT(0)	/* RQ0 */
#define SC5_EVENT_FW                          BIT(1)	/* RQ1 */
#define SC5_EVENT_RADAR_DETECTED              BIT(2)	/* RQ2 */
#define SC5_EVENT_CHAN_SWITCHED               BIT(3)	/* RQ3 */
//NOTE: temporary use RQ4. waiting for fw ready the function, then we can remap other value if need.  
#define SC5_EVENT_ACNT_HEAD_READY             BIT(4)
#if 1				//Notify host to stop/resume tx
#define SC5_EVENT_QUIET                       BIT(5)
#endif

#define SC5_RX_INTR_MASK                      0x0003FF00	// Bit 8-17 : RxQ
#define SC5_RX_INTR_START                     8	// Bit 8-17
#define SC5_TX_INTR_MASK                      0x07800000	// Bit 23-26 :TxQ
#define SC5_BUF_INTR_MASK                     0x003C0000	// Bit 18-21 :BMQ
#define SC5_BUF_RELEASE_MASK                  0x78400000	// Bit 22: SC5, Bit 27-30: RelQ
#define SC5_RXINFO_INTR_MASK                  0x80000000	// Bit 31: Rx Info Acnt Record

//#define SC5_MACREG_REG_INTERRUPT_CAUSE        0x00001060
#define SC5_MACREG_REG_INTERRUPT_CAUSE        0x00001074

// HW revision numbers use as ' if (mainSmacIpRev > SWAR_IP_REV_SC5_Z1) '
#define SWAR_IP_REV_SC5_Z1          0x01003300
#define SWAR_IP_REV_SC5_Z2          0x01003301
#define SWAR_IP_REV_SC5_A0          0x01020300
#define SWAR_IP_REV_SCBT_Z1         0x02010000
#define SWAR_IP_REV_SCBT_A0         0x02020300

// PUNT definition
// ref: 1.14 Punt control (txd1_punt_ctrl) of SMAC_TX_Registers.html
#define 	PUNT_MC2UC_BIT		0x80
#define 	PUNT_L0L1_NO_BUF	0x40
#define		PUNT_ECN_MARK		0x20
#define		PUNT_VLAN_ERR		0x10
#define		PUNT_MTU_LIMIT		0x08
#define		PUNT_AQM_DNY		0x04
#define		PUNT_AQM_ALWS		0x02
#define		PUNT_QID_RESV		0x01
#define		PUNT_ALL			0xff

#define TXD1_PUNT_CTRL				(SC5_REG_SMAC_TXREG_BASE_ADDR + 0x108)
#define TXD1_DDR_DROPBUF_CFG      (SC5_REG_SMAC_TXREG_BASE_ADDR + 0x10C)
#define TXD1_DDR_DROPBUF_RDPTR    (SC5_REG_SMAC_TXREG_BASE_ADDR + 0x110)
#define TXD1_DDR_DROPBUF_WRPTR    (SC5_REG_SMAC_TXREG_BASE_ADDR + 0x114)
#define TXD1_DDR_DROP_WRITE_CNT   (SC5_REG_SMAC_TXREG_BASE_ADDR + 0xE1C)

#define SC5_REG_SMAC_CTRLBASE					0x0001a800
#define SC5_REG_SMAC_TXREG_BASE_ADDR         0x00014000	// txdma.h, bbtx.h
#define SC5_REG_SMAC_CTRLBASE_NSS_PCIE_HI	0x0001a82c

#define SC5_REG_PCIE_INTR_MODE_SEL            0x00030024
#define SC5_REG_PCIE_MSI_ADDR                 0x0003002C
#define SC5_REG_HFRAME_BASE                   0x00030018
#define SC5_REG_PCIE_MSIX_DATA				0x00030028
#define SC5_REG_BASE_ADDR_HOST_128B			0x00030100
#define SC5_REG_FRAME_0						0x00030200
#define SC5_REG_FRAME_1						0x00030204
#define SC5_REG_FRAME_2						0x00030208
#define SC5_REG_FRAME_3						0x0003020C

#define SC5_REG_FRM_SEL_BASE					0x00030300
#define	SC5_REG_FRM_SEL(qid, issq)			(SC5_REG_FRM_SEL_BASE+qid*0x10+issq*8)
#define	SC5_REG_EFF_ID(qid, issq)				(SC5_REG_FRM_SEL(qid, issq)+0x04)

#define SC5_PCIE_MODE_MSI                     0x00000008
#define SC5_PCIE_MODE_MSIX                    0x00000018
#define SC5_PCIE_MODE_GIC                     0x00000038
#define SC5_PCIE_MODE_MSI_2                   0x0000000C
#define SC5_PCIE_MODE_MSIX_2                  0x0000001C
#define SC5_HFRAME_MEM_SIZE                   0x00010000	// 64K

#define IHB_US_REG_SCRATCH0                     0x5950
#define IHB_US_REG_SCRATCH1                     0x5954
#define IHB_US_REG_SCRATCH2                     0x5958
#define IHB_US_REG_SCRATCH3                     0x595C
#define IHB_US_REG_SCRATCH4                     0x5960
#define IHB_US_REG_SCRATCH5                     0x5964
#define IHB_US_REG_SCRATCH6                     0x5968
#define IHB_US_REG_SCRATCH7                     0x596C
#define IHB_US_REG_SCRATCH8                     0x5970
#define IHB_US_REG_SCRATCH9                     0x5974
#define IHB_US_REG_SCRATCH10                    0x5978
#define IHB_US_REG_SCRATCH11                    0x597C
#define IHB_US_REG_SCRATCH12                    0x5980
#define IHB_US_REG_SCRATCH13                    0x5984
#define IHB_US_REG_SCRATCH14                    0x5988

#define MACREG_REG_H2A_INTERRUPT_EVENTS_MCI         0x000059D4	/* (From host to device) */
#define MACREG_REG_H2A_INTERRUPT_CAUSE_MCI          0x000059D8	/* (From host to device) */
#define MACREG_REG_H2A_INTERRUPT_MASK_MCI           0x000059DC	/* (From host to device) */
#define MACREG_REG_H2A_INTERRUPT_CLEAR_SEL_MCI      0x000059E0	/* (From host to device) */
#define MACREG_REG_H2A_INTERRUPT_STATUS_MASK_MCI    0x000059E4	/* (From host to device) */

#define MACREG_REG_A2H_INTERRUPT_EVENTS_MCI         0x000059C0	/* (From device to host) */
#define MACREG_REG_A2H_INTERRUPT_CAUSE_MCI          0x000059C4	/* (From device to host) */
#define MACREG_REG_A2H_INTERRUPT_MASK_MCI           0x000059C8	/* (From device to host) */
#define MACREG_REG_A2H_INTERRUPT_CLEAR_SEL_MCI      0x000059CC	/* (From device to host) */
#define MACREG_REG_A2H_INTERRUPT_STATUS_MASK_MCI    0x000059D0	/* (From device to host) */

#define MACREG_REG_GEN_PTR_MCI                      IHB_US_REG_SCRATCH0
#define MACREG_REG_INT_CODE_MCI                     IHB_US_REG_SCRATCH1
#define MACREG_REG_EVT_RDPTR_MCI                    IHB_US_REG_SCRATCH2
#define MACREG_REG_EVT_WRPTR_MCI                    IHB_US_REG_SCRATCH3

#ifdef NEW_DP
#define MACREG_REG_TxSendHead_MCI                   IHB_US_REG_SCRATCH2
#define MACREG_REG_TxSendTail_MCI                   IHB_US_REG_SCRATCH3
#define MACREG_REG_TxDoneHead_MCI                   IHB_US_REG_SCRATCH4
#define MACREG_REG_TxDoneTail_MCI                   IHB_US_REG_SCRATCH5
#define MACREG_REG_RxDescHead_MCI                   IHB_US_REG_SCRATCH6
#define MACREG_REG_RxDescTail_MCI                   IHB_US_REG_SCRATCH7
#define MACREG_REG_RxDoneHead_MCI                   IHB_US_REG_SCRATCH8
#define MACREG_REG_FwDbgStateAddr_MCI               IHB_US_REG_SCRATCH9
#define MACREG_REG_AcntHead_MCI                     IHB_US_REG_SCRATCH10
#define MACREG_REG_AcntTail_MCI                     IHB_US_REG_SCRATCH11
#define MACREG_REG_OffchReqHead_MCI                 IHB_US_REG_SCRATCH12
#define MACREG_REG_OffchReqTail_MCI                 IHB_US_REG_SCRATCH13
#endif //NEW_DP

//          Map to 0x80000000 (Bus control) on BAR0
#ifdef SOC_W906X
#define MACREG_REG_H2A_INTERRUPT_EVENTS         0x0000105C	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_CAUSE          0x00001060	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_MASK           0x00001064	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_CLEAR_SEL      0x00001068	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_STATUS_MASK    0x0000106C	// (From host to ARM)

#define MACREG_REG_A2H_INTERRUPT_EVENTS         0x00001070	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_CAUSE          0x00001074	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_MASK           0x00001078	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_CLEAR_SEL      0x0000107C	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_STATUS_MASK    0x00001080	// (From ARM to host)

//  Map to 0x80000000 on BAR1
#define MACREG_REG_GEN_PTR                  PCI_REG_SCRATCH0_REG
#define MACREG_REG_INT_CODE                 PCI_REG_SCRATCH1_REG
#define MACREG_REG_EVT_RDPTR                PCI_REG_SCRATCH2_REG
#define MACREG_REG_EVT_WRPTR                PCI_REG_SCRATCH3_REG

//#define MACREG_REG_SCRATCH                  0x00001044//scratch data 2
//#define MACREG_REG_FW_PRESENT                         0x0000BFFC
#ifdef NEW_DP
//#define MACREG_REG_SCRATCH3                 0x00000C44//scratch data 3
#define MACREG_REG_TxSendHead               PCI_REG_SCRATCH2_REG
#define MACREG_REG_TxSendTail               PCI_REG_SCRATCH3_REG
#define MACREG_REG_TxDoneHead               PCI_REG_SCRATCH4_REG
#define MACREG_REG_TxDoneTail               PCI_REG_SCRATCH5_REG
#define MACREG_REG_RxDescHead               PCI_REG_SCRATCH6_REG
#define MACREG_REG_RxDescTail               PCI_REG_SCRATCH7_REG
#define MACREG_REG_RxDoneHead               PCI_REG_SCRATCH8_REG
#define MACREG_REG_FwDbgStateAddr           PCI_REG_SCRATCH9_REG
#define MACREG_REG_AcntHead                 PCI_REG_SCRATCH10_REG
#define MACREG_REG_AcntTail                 PCI_REG_SCRATCH11_REG
#define MACREG_REG_OffchReqHead             PCI_REG_SCRATCH12_REG
#define MACREG_REG_OffchReqTail             PCI_REG_SCRATCH13_REG
#endif //NEW_DP
#else
#define MACREG_REG_H2A_INTERRUPT_EVENTS     	0x00000C18	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_CAUSE      	0x00000C1C	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_MASK       	0x00000C20	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_CLEAR_SEL      0x00000C24	// (From host to ARM)
#define MACREG_REG_H2A_INTERRUPT_STATUS_MASK	0x00000C28	// (From host to ARM)

#define MACREG_REG_A2H_INTERRUPT_EVENTS     	0x00000C2C	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_CAUSE      	0x00000C30	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_MASK       	0x00000C34	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_CLEAR_SEL      0x00000C38	// (From ARM to host)
#define MACREG_REG_A2H_INTERRUPT_STATUS_MASK    0x00000C3C	// (From ARM to host)

//  Map to 0x80000000 on BAR1
#define MACREG_REG_GEN_PTR                  0x00000C10
#define MACREG_REG_INT_CODE                 0x00000C14
#define MACREG_REG_SCRATCH                  0x00000C40
#define MACREG_REG_FW_PRESENT				0x0000BFFC
#ifdef NEW_DP
#define MACREG_REG_SCRATCH3                 0x00000C44
#define MACREG_REG_TxSendHead               0x00000CD0
#define MACREG_REG_TxSendTail               0x00000CD4
#define MACREG_REG_TxDoneHead               0x00000CD8
#define MACREG_REG_TxDoneTail               0x00000CDC
#define MACREG_REG_RxDescHead               0x00000CE0
#define MACREG_REG_RxDescTail               0x00000CE4
#define MACREG_REG_RxDoneHead               0x00000CE8
#define MACREG_REG_RxDoneTail               0x00000CEC
#define MACREG_REG_AcntHead                 0x00000CF0
#define MACREG_REG_AcntTail                 0x00000CF4
#define MACREG_REG_OffchReqHead             0x00000CF8
#define MACREG_REG_OffchReqTail             0x00000CFC
#endif
#endif /* #ifdef SOC_W906X */

//      Bit definitio for MACREG_REG_A2H_INTERRUPT_CAUSE (A2HRIC)
#define MACREG_A2HRIC_BIT_TX_DONE           0x00000001	// bit 0
#define MACREG_A2HRIC_BIT_RX_RDY            0x00000002	// bit 1
#define MACREG_A2HRIC_BIT_OPC_DONE          0x00000004	// bit 2
#define MACREG_A2HRIC_BIT_MAC_EVENT         0x00000008	// bit 3
#define MACREG_A2HRIC_BIT_RX_PROBLEM        0x00000010	// bit 4

#define MACREG_A2HRIC_BIT_RADIO_OFF             0x00000020	// bit 5
#define MACREG_A2HRIC_BIT_RADIO_ON              0x00000040	// bit 6

#define MACREG_A2HRIC_BIT_RADAR_DETECT      0x00000080	// bit 7

#define MACREG_A2HRIC_BIT_ICV_ERROR         0x00000100	// bit 8
#define MACREG_A2HRIC_BIT_WEAKIV_ERROR      0x00000200	// bit 9
#define MACREG_A2HRIC_BIT_QUEUE_EMPTY           (1 << 10)
#define MACREG_A2HRIC_BIT_QUEUE_FULL            (1 << 11)
#define MACREG_A2HRIC_BIT_CHAN_SWITCH      (1 << 12)
#define MACREG_A2HRIC_BIT_TX_WATCHDOG           (1 << 13)
#define MACREG_A2HRIC_BA_WATCHDOG           (1 << 14)
#define MACREG_A2HRIC_CONSEC_TXFAIL             (1 << 17)	//15 taken by ISR_TXACK

#ifdef NEW_DP
#define MACREG_A2HRIC_TX_DESC_TAIL_RDY          (1 << 9)	//Buff removed from Tx Send Ring
#define MACREG_A2HRIC_TX_DONE_HEAD_RDY          (1 << 10)	//Buff added   to   Tx Done Ring
#define MACREG_A2HRIC_ACNT_HEAD_RDY             (1 << 12)	//Records added to Accounting Ring
#define MACREG_A2HRIC_RX_DESC_TAIL_RDY          (1 << 17)	//Buff removed from Rx Desc Ring
#define MACREG_A2HRIC_RX_DONE_HEAD_RDY          (1 << 18)	//Buff added   to   Rx Done Ring
#define MACREG_A2HRIC_NEWDP_OFFCHAN             (1 << 15)
#define MACREG_A2HRIC_NEWDP_SENSORD             (1 << 14)
#define MACREG_A2HRIC_NEWDP_DFS                 (1 << 19)
#define MACREG_A2HRIC_NEWDP_CHANNEL_SWITCH  (1 << 20)
#define MACREG_A2HRIC_BIT_SSU_DONE          (1 << 21)

#ifndef SOC_W906X
#define MACREG_A2HRIC_BIT_MUG_DATA_RDY      (1<<22)
#define MACREG_A2HRIC_BIT_ATF_DATA_RDY      (1<<23)

#define ISR_SRC_BITS        ((MACREG_A2HRIC_ACNT_HEAD_RDY) | \
                             (MACREG_A2HRIC_RX_DONE_HEAD_RDY) | \
                             (MACREG_A2HRIC_NEWDP_OFFCHAN) | \
                             (MACREG_A2HRIC_NEWDP_SENSORD) | \
                             (MACREG_A2HRIC_NEWDP_DFS)     | \
							 (MACREG_A2HRIC_BIT_SSU_DONE)  | \
                             (MACREG_A2HRIC_NEWDP_CHANNEL_SWITCH) | \
                             (MACREG_A2HRIC_BIT_MUG_DATA_RDY) | \
                             (MACREG_A2HRIC_BIT_ATF_DATA_RDY))
#else
#define ISR_SRC_BITS        ((MACREG_A2HRIC_ACNT_HEAD_RDY) | \
			     (MACREG_A2HRIC_RX_DONE_HEAD_RDY) | \
			     (MACREG_A2HRIC_NEWDP_OFFCHAN) | \
			     (MACREG_A2HRIC_NEWDP_SENSORD) | \
			     (MACREG_A2HRIC_NEWDP_DFS)     | \
			     (MACREG_A2HRIC_BIT_SSU_DONE)  | \
			     (MACREG_A2HRIC_NEWDP_CHANNEL_SWITCH))
#endif /* #ifndef SOC_W906X */

#else
#define ISR_SRC_BITS        ((MACREG_A2HRIC_BIT_RX_RDY)   | \
			     (MACREG_A2HRIC_BIT_TX_DONE)  | \
			     (MACREG_A2HRIC_BIT_OPC_DONE) | \
			     (MACREG_A2HRIC_BIT_MAC_EVENT) | \
			     (MACREG_A2HRIC_BIT_WEAKIV_ERROR) | \
			     (MACREG_A2HRIC_BIT_ICV_ERROR) | \
			     (MACREG_A2HRIC_BIT_SSU_DONE) | \
			     (MACREG_A2HRIC_BIT_RADAR_DETECT) | \
			     (MACREG_A2HRIC_BIT_CHAN_SWITCH) | \
			     (MACREG_A2HRIC_BIT_TX_WATCHDOG) | \
			     (MACREG_A2HRIC_BIT_QUEUE_EMPTY) | \
			     (MACREG_A2HRIC_BA_WATCHDOG)        | \
			     (MACREG_A2HRIC_TX_DESC_TAIL_RDY) | \
			     (MACREG_A2HRIC_TX_DONE_HEAD_RDY) | \
			     (MACREG_A2HRIC_ACNT_HEAD_RDY) | \
			     (MACREG_A2HRIC_RX_DESC_TAIL_RDY) | \
			     (MACREG_A2HRIC_RX_DONE_HEAD_RDY) | \
			     (MACREG_A2HRIC_CONSEC_TXFAIL) | \
			     (MACREG_A2HRIC_NEWDP_OFFCHAN) | \
			     (MACREG_A2HRIC_NEWDP_SENSORD) | \
			     (MACREG_A2HRIC_NEWDP_DFS))
#endif

#define MACREG_A2HRIC_BIT_MASK      ISR_SRC_BITS & (~MACREG_A2HRIC_BIT_TX_DONE)
#define MACREG_HFCTRL_MASK                      0x01ffff00

#define MACREG_A2HRIC_BIT_MASK_MSI	0xffffffff
#define MACREG_HFCTRL_MASK_MSI		0xffffffff

//      Bit definitio for MACREG_REG_H2A_INTERRUPT_CAUSE (H2ARIC)
#define MACREG_H2ARIC_BIT_PPA_READY         0x00000001	// bit 0
#define MACREG_H2ARIC_BIT_DOOR_BELL         0x00000002	// bit 1
#define MACREG_H2ARIC_BIT_PS                    0x00000004	// bit 2
#define MACREG_H2ARIC_BIT_PSPOLL                0x00000008	// bit 3
#define ISR_RESET                                       (1 << 15)
#define ISR_RESET_AP33                                  (1 << 26)

// Power Save events
#define MACREG_PS_OFF                                           0x00000000
#define MACREG_PS_ON                                            0x00000001

//      INT code register event definition
#define MACREG_INT_CODE_TX_PPA_FREE         0x00000000
#define MACREG_INT_CODE_TX_DMA_DONE         0x00000001
#define MACREG_INT_CODE_LINK_LOSE_W_SCAN    0x00000002
#define MACREG_INT_CODE_LINK_LOSE_NO_SCAN   0x00000003
#define MACREG_INT_CODE_LINK_SENSED         0x00000004
#define MACREG_INT_CODE_CMD_FINISHED        0x00000005
#define MACREG_INT_CODE_MIB_CHANGED         0x00000006
#define MACREG_INT_CODE_INIT_DONE           0x00000007
#define MACREG_INT_CODE_DEAUTHENTICATED     0x00000008
#define MACREG_INT_CODE_DISASSOCIATED       0x00000009

#endif /* AP8X_REGS_H_ */
