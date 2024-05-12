/** @file hal_hiu.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
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
#ifndef _HAL_HIU_H_
#define _HAL_HIU_H_

#include "memmap.h"
#include "hal_ihb_us.h"
extern boolean strap_mode_pcie;

#define PCI_INTR_TYPE_DEFAULT        0
#define PCI_INTR_TYPE_MSI            1
#define PCI_INTR_TYPE_MSIX           2

#define CBP_EV_WCB_RECEIVED        (1<<0)
#define CBP_EV_HOST_OPC_RECEIVED   (1<<1)
#define CBP_EV_DMA_DONE            (1<<2)
#define CBP_EV_TX_DONE             (1<<3)
#define CBP_EV_MGMT_MSG_RCVD       (1<<4)
#define CBP_EV_SME_MSG_RCVD        (1<<5)
#define CBP_EV_CBP_MSG_RCVD        (1<<6)
#define CBP_EV_RX_BA               (1<<8)
#define CBP_EV_BCN_FOUND           (1<<9)
#define CBP_EV_USB_DATA_RCVD       (1<<10)
#define CBP_EV_USB_MGMT_RCVD       (1<<11)
#define CBP_EV_KEEP_ALIVE          (1<<12)

#define CBP_EV_PS_AWAKE            (1<<12)
#define CBP_EV_PS_ASLEEP           (1<<13)
#define CBP_EV_PS_FROMHOST         (1<<14)

#define CBP_EV_DBG_ISRSENDMSG      (1<<15)

#define PCI_MSI_RADAR_DETECT_AUX    0
#define PCI_MSI_EVENT_FW            1
#define PCI_MSI_RADAR_DETECT_MAIN   2
#define PCI_MSI_CHAN_SWITCH         3
#define PCI_MSI_ACNT_HEAD_READY     4
#if 1				//Notify host to stop/resume tx
#define PCI_MSI_QUIET               5
#endif

/************************************************************************
* PCI-express Host Interface registers
************************************************************************/
#define PEHI_REG_ADDR(offset) (HAL_HIU_CFG_BASE + offset)

#define HAL_PEHI_REG_PMCTRL         PEHI_REG_ADDR(0x084)
#define PEHI_PMCTRL_GATECLK        (1 << 0)
#define PEHI_PMCTRL_CLKREQFORCEON  (1 << 4)
#define PEHI_PMCTRL_CLKREQPINLOW   (1 << 5)
#define PEHI_PMCTRL_FWL1ASPMREQ    (1 << 14)
#define HAL_PEHI_REG_PMMASK         PEHI_REG_ADDR(0x088)
#define PEHI_PMMASK_FWGENGATE      (1 << 0)
#define PEHI_PMMASK_EIGENGATE      (1 << 1)
#define PEHI_PMMASK_FWRELGATE      (1 << 16)
#define PEHI_PMMASK_EIRELGATE      (1 << 17)
#define HAL_PEHI_REG_UNCORR_ERR_SEV PEHI_REG_ADDR(0x10c)
#define PEHI_UES_FC_PROT_ERR_SEV   (1 << 13)
#define HAL_PEHI_REG_CTRL2          PEHI_REG_ADDR(0xc64)
#define PEHI_CTRL2_TSTBUSCTRL_MASK    (0xf << 8)
#define PEHI_CTRL2_TSTBUSCTRL_TGTSM   (0x9 << 8)
#define PEHI_CTRL2_SWCLKREQ           (1 << 30)
#define PEHI_CTRL2_SWL1ASPMREQ        ((unsigned int) 1 << 31)
#define HAL_PEHI_REG_PHY_REG_ACC    PEHI_REG_ADDR(0xc70)
#define PEHI_PHY_REG_ACC_WR        0
#define PEHI_PHY_REG_ACC_RD        ((unsigned int) 1 << 31)
#define PEHI_PHY_REG_ACC_ADDR_SHFT 16
#define PEHI_PHY_REG_ACC_DATA_MASK 0xffff
#define HAL_PEHI_REG_CTRL3_SJAY     PEHI_REG_ADDR(0xc9c)
#define PEHI_CTRL3_TCLKCTRL_MASK                  0x1f
#define PEHI_CTRL3_TCLKCTRL_ON                    (1 << 0)
#define PEHI_CTRL3_TCLKCTRL_NOPM2PHYCLKOFF        (1 << 1)
#define PEHI_CTRL3_TCLKCTRL_NOSYS2PEXCLKREQOFF    (1 << 2)
#define PEHI_CTRL3_TCLKCTRL_NOELECIDLE            (1 << 3)
#define PEHI_CTRL3_TCLKCTRL_NOL1IDLE              (1 << 4)
#define PEHI_CTRL3_HOSTWAKE_MASK                  (0x1f << 11)
#define PEHI_CTRL3_HOSTWAKE_ON                    (1 << 11)
#define PEHI_CTRL3_HOSTWAKE_NOELECIDLE            (1 << 12)
#define PEHI_CTRL3_HOSTWAKE_NOPM2PHYCLKOFF        (1 << 13)
#define PEHI_CTRL3_HOSTWAKE_SOCACCESS             (1 << 14)
#define PEHI_CTRL3_HOSTWAKE_LINKRESTART           (1 << 15)
#define PEHI_CTRL3_EN_DRIVER_WAKE                 (1 << 16)

/************************************************************************
* PCI-express PHY register addresses accessible through register
* 0xc70 in the host interface above (HAL_PEHI_REG_PHY_REG_ACC)
************************************************************************/
#define PCIE_PHY_REG_MONITOR    0x02
#define PCIE_PHY_MONITOR_PM_STATE_MASK    0xf
#define PCIE_PHY_MONITOR_PM_STATE_SP1     0x5
#define PCIE_PHY_MONITOR_PM_STATE_SP1PARK 0xf

/* PCI Host Interface registers */
#define PHI_REG_ADDR(offset) ((HAL_HIU_CFG_BASE) | offset)

#define HAL_PCI_REG_PCI_CMPL_TOUT    PHI_REG_ADDR(0x0220)
#define PCI_CMPL_TOUT_MASK    0xffff
#define PCI_CMPL_TOUT_DSBL    0x0

#define HAL_PCI_REG_DOORBELL       PHI_REG_ADDR(0x0948)
#define HAL_PCI_REG_PCICFGARRD     PHI_REG_ADDR(0x0CF8)
#define HAL_PCI_REG_PCICFGDATA     PHI_REG_ADDR(0x0CFC)

#define HAL_PCI_REG_CONTROL     PHI_REG_ADDR(0x1000)
#define PCI_CONTROL_THRTL_RD_ENBL    (1<<29)
#define PCI_CONTROL_INT_2PE_PINGP    (1<<31)

#define HAL_PCI_REG_BAR0_SIZE       PHI_REG_ADDR(0x1004)
#define HAL_PCI_REG_BAR1_SIZE       PHI_REG_ADDR(0x1008)
#define HAL_PCI_REG_BAR0_RMAP       PHI_REG_ADDR(0x100C)
#define HAL_PCI_REG_BAR1_RMAP       PHI_REG_ADDR(0x1010)
#define HAL_PCI_REG_BAR2_RMAP       PHI_REG_ADDR(0x1014)
#define HAL_PCI_REG_REMAP_EXT        PHI_REG_ADDR(0x1018)
#define HAL_PCI_REG_SCRATCH0_REG    PHI_REG_ADDR(0x101C)
#define HAL_PCI_REG_SCRATCH1_REG    PHI_REG_ADDR(0x1020)
#define HAL_PCI_REG_SCRATCH2_REG    PHI_REG_ADDR(0x1024)
#define HAL_PCI_REG_SCRATCH3_REG    PHI_REG_ADDR(0x1028)
#define HAL_PCI_REG_SCRATCH4_REG    PHI_REG_ADDR(0x102c)
#define HAL_PCI_REG_SCRATCH5_REG    PHI_REG_ADDR(0x1030)
#define HAL_PCI_REG_SCRATCH6_REG    PHI_REG_ADDR(0x1034)
#define HAL_PCI_REG_SCRATCH7_REG    PHI_REG_ADDR(0x1038)
#define HAL_PCI_REG_SCRATCH8_REG    PHI_REG_ADDR(0x103c)
#define HAL_PCI_REG_SCRATCH9_REG    PHI_REG_ADDR(0x1040)
#define HAL_PCI_REG_SCRATCH10_REG    (strap_mode_pcie?PHI_REG_ADDR(0x1044):ihb_us_WF1_CFG_SCRATCH10)
#define HAL_PCI_REG_SCRATCH11_REG    (strap_mode_pcie?PHI_REG_ADDR(0x1048):ihb_us_WF1_CFG_SCRATCH11)
#define HAL_PCI_REG_SCRATCH12_REG    PHI_REG_ADDR(0x104c)
#define HAL_PCI_REG_SCRATCH13_REG    PHI_REG_ADDR(0x1050)
#define HAL_PCI_REG_SCRATCH14_REG    PHI_REG_ADDR(0x1054)
#define HAL_PCI_REG_SCRATCH15_REG    PHI_REG_ADDR(0x1058)

#define HAL_PCI_REG_GEN_PTR     HAL_PCI_REG_SCRATCH0_REG
#define HAL_PCI_REG_INTCODE     HAL_PCI_REG_SCRATCH1_REG
#define HAL_IHB_REG_GEN_PTR     ihb_us_WF1_CFG_SCRATCH0
#define HAL_IHB_REG_INTCODE     ihb_us_WF1_CFG_SCRATCH1

#define HAL_PCI_REG_EVT_RDPTR   HAL_PCI_REG_SCRATCH2_REG
#define HAL_PCI_REG_EVT_WRPTR   HAL_PCI_REG_SCRATCH3_REG
#define HAL_IHB_REG_EVT_RDPTR   ihb_us_WF1_CFG_SCRATCH2
#define HAL_IHB_REG_EVT_WRPTR   ihb_us_WF1_CFG_SCRATCH3

#define HAL_PCI_REG_ITR         PHI_REG_ADDR(0x105c)
#define HAL_PCI_REG_ISR         PHI_REG_ADDR(0x1060)	//interrupt status
#define HAL_PCI_REG_IMR         PHI_REG_ADDR(0x1064)	//interrupt mask
#define HAL_PCI_REG_RSR         PHI_REG_ADDR(0x1068)
#define HAL_PCI_REG_SMR         PHI_REG_ADDR(0x106c)	//interrupt status mask
#define HAL_PCI_REG_HOST_ITR    PHI_REG_ADDR(0x1070)
#define HAL_PCI_REG_HOST_ISR    PHI_REG_ADDR(0x1074)	//interrupt status
#define HAL_PCI_REG_HOST_IMR    PHI_REG_ADDR(0x1078)	//interrupt mask
#define HAL_PCI_REG_HOST_RSR    PHI_REG_ADDR(0x107c)
#define HAL_PCI_REG_HOST_SMR    PHI_REG_ADDR(0x1080)

#define HAL_PCI_IP_REVISION_REG       PHI_REG_ADDR(0x1084)
#define HAL_PCI_HOST_REMAP_REG        PHI_REG_ADDR(0x1088)
#define HAL_PCI_HOST_REMAP_L2_REG   PHI_REG_ADDR(0x108c)
#define HAL_PCI_HOST_REMAP0_REG        PHI_REG_ADDR(0x1090)

#define PPA_SIZE        32
#define DPA_SIZE        32
#define WCB_ARRAY_SIZE  32*8
#define FW_WCB_SIZE    32

#define FW_PRESENT     0xF4F2F1F0
#define FW_PRESENT_WORD     0xC000bffc

#define ISR_PS_OFF            0
#define ISR_PS_ON            1

/* Bit definitions for HAL_PCI_REG_ISR */
#define ISR_PPA_RDY         (1<<0)	// Host to ARM will be 24 - 31
#define ISR_DOORBELL        (1<<1)
#define ISR_FROMHOST_PS        (1<<2)
#define ISR_FROMHOST_PSPOLL    (1<<3)
#define ISR_FROMHOST_RXIRQ    (1<<4)
//#define ISR_RESET           (1<<26) //the bit 26 was used by power mgnt
#define ISR_RESET           (1<<15)	//in new piu
#define ISR_RETRYEXPIRED    (1<<27)

/* Bit definitions for HAL_PCI_REG_IMR */
#define IMR_PPA_RDY         (1<<0)
#define IMR_DOORBELL        (1<<1)
#define IMR_FROMHOST_PS        (1<<2)
#define IMR_FROMHOST_PSPOLL    (1<<3)
#define IMR_FROMHOST_RXIRQ    (1<<4)
#define IMR_RESET           (1<<15)
#define IMR_RETRYEXPIRED    (1<<27)

#define PIU_MASK            (1<<0)	// 1 = Mask PIU interrupt to ARM

/* Bit definitions for HAL_PCI_REG_ICR */
#define ICR_PPA_RDY         (1<<0)
#define ICR_DOORBELL        (1<<1)
#define ICR_FROMHOST_PS     (1<<2)
#define ICR_FROMHOST_PSPOLL    (1<<3)
#define ICR_RESET           (1<<15)
#define ICR_RETRYEXPIRED    (1<<27)

/* Bit definitions for HAL_PCI_REG_RSR */
#define RSR_PPA_RDY         (1<<0)
#define RSR_DOORBELL        (1<<1)
#define RSR_FROMHOST_PS        (1<<2)
#define RSR_FROMHOST_PSPOLL    (1<<3)
#define RSR_FROMHOST_RXIRQ    (1<<4)
#define RSR_RESET           (1<<15)
#define RSR_RETRYEXPIRED    (1<<27)

/* Bit definitions for HAL_PCI_REG_HOST_ISR */
#define ISR_TXDONE          (1<<0)
#define ISR_RXDONE          (1<<1)
#define ISR_OPCDONE         (1<<2)
#define ISR_MACEVENTS       (1<<3)
#define ISR_TOHOST_PS       (1<<4)
#define ISR_RF_OFF          (1<<5)
#define ISR_RF_ON           (1<<6)
#define ISR_RADAR_DETECT_MAIN  (1<<7)
#define ISR_RADAR_DETECT_AUX   (1<<8)
#define ISR_ENCR_MIC_ERROR  (1<<9)
#ifdef BUILT_NETBSD
#define ISR_BA_WATCHDOG     (1<<10)
#define ISR_QUEUE_EMPTY     (1<<14)
#else
#define ISR_QUEUE_EMPTY     (1<<10)
#endif
#define ISR_QUEUE_FULL        (1<<11)
#define ISR_CHAN_SWITCH        (1<<12)
#define ISR_TX_WATCHDOG        (1<<13)
#ifndef BUILT_NETBSD
#define ISR_BA_WATCHDOG        (1<<14)
#endif
#define ISR_TXACK           (1<<15)
#ifdef SSU_SUPPORT
#define ISR_SSU_DONE        (1<<16)
#endif
#define ISR_CONSEC_TXFAIL    (1<<17)
#define ISR_ANCT_HEAD       (1<<18)
#if 1				//Notify host to stop/resume tx
#define ISR_QUIET           (1<<19)
#endif
/* Bit definitions for HAL_PCI_REG_HOST_IMR */
#define IMR_TXDONE          (1<<0)
#define IMR_RXDONE          (1<<1)
#define IMR_OPCDONE         (1<<2)
#define IMR_MACEVENTS       (1<<3)
#define IMR_TOHOST_PS       (1<<4)
#define IMR_RF_OFF          (1<<5)
#define IMR_RF_ON           (1<<6)
#define IMR_RADAR_DETECT    (1<<7)
#define IMR_ENCR_ICV_ERROR  (1<<8)
#define IMR_ENCR_MIC_ERROR  (1<<9)
#ifdef BUILT_NETBSD
#define IMR_BA_WATCHDOG     (1<<10)
#define IMR_QUEUE_EMPTY     (1<<14)
#else
#define IMR_QUEUE_EMPTY     (1<<10)
#endif
#define IMR_QUEUE_FULL        (1<<11)
#define IMR_CHAN_SWITCH        (1<<12)
#define IMR_TX_WATCHDOG        (1<<13)
#ifndef BUILT_NETBSD
#define IMR_BA_WATCHDOG        (1<<14)
#endif
#define IMR_TXACK           (1<<15)
#ifdef SSU_SUPPORT
#define IMR_SSU_DONE        (1<<16)
#endif
#define IMR_CONSEC_TXFAIL    (1<<17)

/* New in Rev4 chip */
#define IMR_INT_DISABLE     (1<<16)
#define IMR_HOST_MASK       (1<<0)	// 1 = mask pci interrupt to host

/* Bit definitions for HAL_PCI_REG_HOST_RSR */
#define RSR_TXDONE          (1<<0)
#define RSR_RXDONE          (1<<1)
#define RSR_OPCDONE         (1<<2)
#define RSR_MACEVENTS       (1<<3)
#define RSR_TOHOST_PS       (1<<4)
#define RSR_RF_OFF          (1<<5)
#define RSR_RF_ON           (1<<6)
#define RSR_RADAR_DETECT    (1<<7)
#define RSR_ENCR_ICV_ERROR  (1<<8)
#define RSR_ENCR_MIC_ERROR  (1<<9)
#ifdef BUILT_NETBSD
#define RSR_BA_WATCHDOG     (1<<10)
#define RSR_QUEUE_EMPTY     (1<<14)
#else
#define RSR_QUEUE_EMPTY     (1<<10)
#endif
#define RSR_QUEUE_FULL        (1<<11)
#define RSR_CHAN_SWITCH        (1<<12)
#define RSR_TX_WATCHDOG        (1<<13)
#ifndef BUILT_NETBSD
#define RSR_BA_WATCHDOG        (1<<14)
#endif
#define RSR_TXACK           (1<<15)
#ifdef SSU_SUPPORT
#define RSR_SSU_DONE        (1<<16)
#endif
#define RSR_CONSEC_TXFAIL    (1<<17)

/* Bit definitions for HAL_PCI_REG_HOST_SMR */
#define SMR_TXDONE          (1<<0)
#define SMR_RXDONE          (1<<1)
#define SMR_OPCDONE         (1<<2)
#define SMR_MACEVENTS       (1<<3)
#define SMR_TOHOST_PS       (1<<4)
#define SMR_RF_OFF          (1<<5)
#define SMR_RF_ON           (1<<6)
#define SMR_RADAR_DETECT    (1<<7)
#define SMR_ENCR_ICV_ERROR  (1<<8)
#define SMR_ENCR_MIC_ERROR  (1<<9)
#ifdef BUILT_NETBSD
#define SMR_BA_WATCHDOG     (1<<10)
#define SMR_QUEUE_EMPTY     (1<<14)
#else
#define SMR_QUEUE_EMPTY     (1<<10)
#endif
#define SMR_QUEUE_FULL        (1<<11)
#define SMR_CHAN_SWITCH        (1<<12)
#define SMR_TX_WATCHDOG        (1<<13)
#ifndef BUILT_NETBSD
#define SMR_BA_WATCHDOG        (1<<14)
#endif
#define SMR_TXACK           (1<<15)
#ifdef SSU_SUPPORT
#define SMR_SSU_DONE        (1<<16)
#endif
#define SMR_CONSEC_TXFAIL    (1<<17)

#define HAL_HIU_TYPE_PCI     0x0
#define HAL_HIU_TYPE_CARDBUS 0x1
#define HAL_HIU_TYPE_PCIE    0x2

//#define ADMA_SINGLE_DESCRIPTOR_CHAIN

extern u32 hal_hiu_get_type(void);
extern void hal_hiu_write_host_window(u8 * dst, u8 * src, u32 len, u8 window_idx);
extern void hal_hiu_init(void);
extern void hal_hiu_get_config(u32 *);
extern void hal_hiu_reset(void);
extern void hwi_hiu_tx_done(void *);
#ifndef SOC_W9068

extern rx_wcb_t *hal_hiu_get_rx_wcb(void);
extern void hal_hiu_put_rx_wcb(rx_wcb_t *);
#endif
extern u8 *hal_hiu_get_cmd_in_buf(void);
extern u8 *hal_hiu_get_cmd_out_buf(void);
void hal_reset_cmd_ptr(void);
extern void hal_hiu_notify_host(u32);
extern void hal_hiu_set_fw_ready(void);
typedef struct {
	u32 location;
	u32 timestamp;
} trace_t;
typedef struct {
	/* 0x00: */
	u32 dram_test_good_cnt;	/* Also heartbeat for diag mode */
	u32 dram_test_bad_cnt;	/* Also indicator for diag mode */
	s8 *cmd_stack;
	u32 *debug_ptr;
	/* 0x10: */
	u32 debug_start;	/* start of debug buffer  */
	u32 debug_size;		/* length of debug buffer */
	u32 debug_allow;	/* zero to disable debug buffer */
	u16 debug_count;	/* count down to debug disable */
	u16 debug_value;	/* parameter for faster retry rate drop */
	/* 0x20: */
	u32 stadb_add_stat;
	u32 stadb_del_stat;
	u32 stadb_comm_stat;
	u32 stadb_dump_stat;
	/* 0x30: */
	u32 adma2_4_ctr;
	u32 adma2_4_src;
	u32 cmd_debug;
	u32 cmd_val;
	/* 0x40: */
	u32 phy_hal_state;	/* PHY HAL Operating State */
	u32 debugbits;
	u32 host_irq_status;
	u32 host_process_events;
	/* 0x50: *//* WARNING: */
	u32 bad_vector_val;	/* hardcoded offset in tx_b*.s !!! */
	u32 bad_vector_fsr;	/* hardcoded offset in tx_b*.s !!! */
	u32 bad_vector_far;	/* hardcoded offset in tx_b*.s !!! */
	u32 pc;
	/* 0x60-BF: *//* WARNING: */
	/* R0-R12, SP, LR, CPSR, bad vec CPSR and SP */
	u32 diag_mode_regs[13];	/* hardcoded offset in tx_b*.s !!! */
	u32 diag_mode_sp;	/* hardcoded offset in tx_b*.s !!! */
	u32 diag_mode_lr;	/* hardcoded offset in tx_b*.s !!! */
	u32 diag_mode_cpsr;	/* hardcoded offset in tx_b*.s !!! */
	/* 0xA0: */
	u32 diag_mode_bv_pc;	/* hardcoded offset in tx_b*.s !!! */
	u32 diag_mode_bv_sp;	/* hardcoded offset in tx_b*.s !!! */
	u32 diag_mac_intr_mask;
	u32 diag_mac_rx_mode;
	/* 0xB0 */
	/* Determine - which threads are alive and executing */
	u32 cmd_thread_alive;
	u32 sche_thread_alive;
	u32 idle_thread_alive;
	u32 udp_thread_alive;

	/* 0xC0 */
	/* Determine - whether host commands are executing properly */
	u32 ev_state;
	u32 signal_proc_ts;
	u32 last_ev_cmd_ts;
	u32 h2a_status_ts;

	/* Rx stage counters */
	/* 0xD0 */
	u32 rx_stg1_rxdone_irq;
	u32 rx_stg2_rxprocbufs;
	u32 rx_stg3_ecu_start;
	u32 rx_stg4_ecu_done;
	/* 0xE0 */
	u32 rx_stg5_deagg_tohost;
	u32 rxDrops;
	u32 rx_stg6_rxdeliverdone;
	u32 off_channel_req;
	/* 0xF0: */
	u32 off_channel_pend;
	u32 off_channel_start;
	u32 off_channel_done;
	u32 offChanDoneQFull;
	/* 0x100: */
	u32 off_channel_truncated;
	u32 avail_main_pool;
	u32 avail_internal_pool;
	u32 avail_main_pool_cached;
	/* 0x110: */
	u32 avail_internal_pool_cached;
	u32 avail_fast_pool;
	u32 remove_sta_ac_link_cnt;
	u32 last_thread;	/* WARNING: hardcoded offset in */
	/* 0x120: */
	u32 debug_count0;
	u32 debug_count1;
	u32 ps_mcbc;
	u32 ps_mcbcbuffered;
	/* 0x130: */
	u32 ps_mcbcbufferedreset;
	u32 schedulercount;
	u32 schedulercount1;
	u32 schedulercount2;
	/* 0x140 */
	u32 schedulercount3;
	u32 schedulercount4;
	u32 schedulercount5;
	u32 schedulercount6;
	/* 0x150 */
	u32 ps_enqcnt;
	u32 ps_deqcnt;
	u32 ps_timcnt;
	u32 tracelogindex2:8;
	u32 tracelogindex1:8;
	u32 tracelogindex:16;
	/* 0x160 */
	u32 cm3_0_pc;
	u32 cm3_1_pc;
	u32 cm3_2_pc;
	u32 cm3_3_pc;
	/* 0x170 */
	u32 cm3_4_pc;
	u32 cm3_5_pc;
	u32 cm3_6_pc;
	u32 trg_enqcnt:16;
	u32 schedulercount7:16;
	/* 0x180 */
	trace_t tracelog2[32];
	/* 0x280 */
	trace_t tracelog1[32];
	/* 0x380 */
	trace_t tracelog[(0x800 - 0x80 - 0x380) / sizeof(trace_t)];

}
debug_state_t;
extern debug_state_t debug_state;

//#define DEBUG_STATE.adma2_4_ctr gSmacCtrlBlk->sfw.adma2_4_ctr
//#define DEBUG_STATE.adma2_4_src gSmacCtrlBlk->sfw.adma2_4_src
//#define DEBUG_STATE.cmd_debug gSmacCtrlBlk->sfw.cmd_debug
//#define DEBUG_STATE.cmd_val gSmacCtrlBlk->sfw.cmd_val

#define DEBUG_STATE     (debug_state)

//only use DEBUGTRACE 
#define DEBUGTRACE2(bit,x,y) if(DEBUG_STATE.debug_allow & (1<<bit)){\
                                DEBUG_STATE.tracelog2[DEBUG_STATE.tracelogindex2].location = (u32)x;\
                                DEBUG_STATE.tracelog2[DEBUG_STATE.tracelogindex2].timestamp = (u32)y;\
                                     if(++DEBUG_STATE.tracelogindex2==32)DEBUG_STATE.tracelogindex2=0;}

#define DEBUGTRACE1(bit,x,y) if(DEBUG_STATE.debug_allow & (1<<bit)){\
                                DEBUG_STATE.tracelog1[DEBUG_STATE.tracelogindex1].location = (u32)x;\
                                DEBUG_STATE.tracelog1[DEBUG_STATE.tracelogindex1].timestamp = (u32)y;\
                                     if(++DEBUG_STATE.tracelogindex1==32)DEBUG_STATE.tracelogindex1=0;}

#define DEBUGTRACE(bit,x,y) if(DEBUG_STATE.debug_allow & (1<<bit)){\
                                DEBUG_STATE.tracelog[DEBUG_STATE.tracelogindex].location = (u32)x;\
                                DEBUG_STATE.tracelog[DEBUG_STATE.tracelogindex].timestamp = (u32)y;\
                                     if(++DEBUG_STATE.tracelogindex==((0x800-0x80-0x380)/sizeof(trace_t)))DEBUG_STATE.tracelogindex=0;}

#define DEBUG_TRACE(x)       DEBUGTRACE(3,__LINE__,x)

#endif				/* _HAL_HIU_H_ */
