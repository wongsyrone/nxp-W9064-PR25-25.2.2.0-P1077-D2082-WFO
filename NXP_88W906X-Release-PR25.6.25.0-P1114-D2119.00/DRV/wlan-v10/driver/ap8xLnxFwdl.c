/** @file ap8xLnxFwdl.c
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
#ifndef NEW_DP
#ifdef DEFAULT_MFG_MODE
#include "88W8764-mfg.h"
#else
#include "88W8764.h"
#endif
#else
/* NEW_DP */
#ifndef SOC_W906X
#include "sc3_ddr.h"
#include "sc4_ddr.h"
#endif				/* #ifndef SOC_W906X */
#endif

#include "ap8xLnxVer.h"
#include "ap8xLnxFwdl.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxIntf.h"
#include "wldebug.h"
#if defined (MFG_SUPPORT)
#include "wl_mib.h"
#include "wl_hal.h"
#endif

#ifdef FS_CAL_FILE_SUPPORT
#include "shal_cpu.h"
#endif

/* default settings */

/** external functions **/

/** external data **/

/** public data **/
/** private data **/

/** local definitions **/
#define FW_MAX_CHUNK_LEN                2048

#define FW_CHECK_MSECS                  1
#define FW_MAX_NUM_CHECKS               0xffff

#ifdef SOC_W906X
static void fw_chunk_transfer(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int reg_event_offset = wlpptr->wlpd_p->reg.fw_int_event_offeset;
	unsigned int reg_gen_ptr = wlpptr->wlpd_p->reg.gen_ptr;

	/* write location of data */
	writel(wlpptr->wlpd_p->pPhysFwDlBuf, wlpptr->ioBase1 + reg_gen_ptr);

	/* inform bootcode */
	writel(MACREG_H2ARIC_BIT_DOOR_BELL, wlpptr->ioBase1 + reg_event_offset);
}

static inline void fw_setup_intr(struct wlprivate *wlpptr)
{
	unsigned int trigger = wlpptr->wlpd_p->reg.fw_setup_int_trigger;
	unsigned int reg_a2h_intr_clear_sel = wlpptr->wlpd_p->reg.a2h_int_clear_sel;
	unsigned int reg_a2h_intr_cause = wlpptr->wlpd_p->reg.a2h_int_cause;
	unsigned int reg_a2h_intr_mask = wlpptr->wlpd_p->reg.a2h_int_mask;
	unsigned int reg_a2h_status_mask = wlpptr->wlpd_p->reg.a2h_int_status_mask;

	writel(MACREG_A2HRIC_BIT_MASK, wlpptr->ioBase1 + reg_a2h_intr_clear_sel);
	writel(0x00, wlpptr->ioBase1 + reg_a2h_intr_cause);
	writel(0x00, wlpptr->ioBase1 + reg_a2h_intr_mask);
	writel(trigger, wlpptr->ioBase1 + reg_a2h_status_mask);
}
#endif				/* #ifdef SOC_W906X */

#define FW_DOWNLOAD_BLOCK_SIZE                 256
#define FW_CHECK_MSECS                           1

#define FW_MAX_NUM_CHECKS                      0xffff	/* why is this needed? */

#define FW_LOAD_STA_FWRDY_SIGNATURE     0xf0f1f2f4
#define FW_LOAD_SOFTAP_FWRDY_SIGNATURE  0xf1f2f4a5

#define HostCmd_STA_MODE     0x5A
#define HostCmd_SOFTAP_MODE  0xA5

#define WL_SEC_SLEEP(NumSecs)       mdelay(NumSecs * 1000);
#define WL_MSEC_SLEEP(NumMilliSecs) mdelay(NumMilliSecs);

/** internal functions **/
#ifndef SOC_W906X
static void wltriggerPciCmd(struct net_device *);
#endif
static void wltriggerPciCmd_bootcode(struct net_device *);

#ifdef SOC_W906X
extern u64 xxGetTimeStamp(void);
extern int reset_mode;
#endif				/* #ifdef SOC_W906X */

/** public functions **/
int wlFwDownload(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	const unsigned char *pFwImage = NULL;
	u32 fw_img_len = 0;
	unsigned int currIteration = FW_MAX_NUM_CHECKS;
	//unsigned short firmwareBlockSize = FW_DOWNLOAD_BLOCK_SIZE;
	unsigned int FwReadySignature = FW_LOAD_STA_FWRDY_SIGNATURE;
	unsigned int OpMode = HostCmd_STA_MODE;

#ifdef SOC_W906X
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u64 tick1, tick2, tick3;
	u64 tick4 = 0;

	unsigned int reg_len_offset = wlpptr->wlpd_p->reg.fw_len_offset;
	unsigned int reg_cause_offset = wlpptr->wlpd_p->reg.fw_int_cause_offset;
	unsigned int reg_gen_ptr = wlpptr->wlpd_p->reg.gen_ptr;
	unsigned int reg_int_code = wlpptr->wlpd_p->reg.int_code;
#else
	unsigned int reg_cause_offset = MACREG_REG_H2A_INTERRUPT_CAUSE;
	unsigned int reg_gen_ptr = MACREG_REG_GEN_PTR;
	unsigned int reg_int_code = MACREG_REG_INT_CODE;
	unsigned int downloadSuccessful = 1;
#endif				/* #ifdef SOC_W906X */

	unsigned int sizeFwDownloaded = 0;
	//unsigned int remainingFwBytes = 0;
	unsigned int intCode;
	//unsigned int sizeSend = 0;
	//unsigned int sizeGood = 0;
	//unsigned int i,       sizeBlock;
	//unsigned char useHelp = 0;
	//unsigned long dummy;
	unsigned int len;

#ifndef SOC_W906X
#ifdef NEW_DP
	unsigned int sizeDdrInit = sizeof(ddr_init);
	unsigned char *p = (unsigned char *)&ddr_init[0];
	unsigned int sizeDdrInitDownloaded = 0;

	if ((wlpptr->devid == SC4) || (wlpptr->devid == SC4P)) {
		sizeDdrInit = sizeof(sc4_ddr_init);
		p = (unsigned char *)&sc4_ddr_init[0];
	}
#endif
#endif				/* #ifndef SOC_W906X */

	WLDBG_ENTER(DBG_LEVEL_3);

	if (wlpptr->fw_entry) {
		pFwImage = wlpptr->fw_entry->data;
		fw_img_len = wlpptr->fw_entry->size;
	} else {
		pFwImage = wlpptr->FwPointer;
		fw_img_len = wlpptr->FwSize;
	}

#ifdef SOC_W906X
	if (IS_BUS_TYPE_MCI(wlpptr)) {
		FwReadySignature = HostCmd_SOFTAP_FWRDY_SIGNATURE;
		OpMode = HostCmd_SOFTAP_MODE;
	} else {
		FwReadySignature = FW_LOAD_STA_FWRDY_SIGNATURE;
		OpMode = HostCmd_STA_MODE;
		wlpd_p->downloadSuccessful = 1;
	}
#endif				/* #ifdef SOC_W906X */
#ifdef NO_FW_DOWNLOAD
	printk("AP8X: This version does not support host fwdl!!!\n");
	return SUCCESS;
#endif

	wlFwReset(netdev);

#ifdef SOC_W906X
	if (IS_BUS_TYPE_MCI(wlpptr)) {
		//FW before jumping to boot rom, it will enable PCIe transaction retry,
		//wait for boot code to stop it.
		mdelay(FW_CHECK_MSECS);

		fw_setup_intr(wlpptr);
	} else {
#endif				/* #ifdef SOC_W906X */
		//FW before jumping to boot rom, it will enable PCIe transaction retry, wait for boot code to stop it.
		WL_MSEC_SLEEP(FW_CHECK_MSECS);

		writel(MACREG_A2HRIC_BIT_MASK_MSI, wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_CLEAR_SEL);
		writel(0x00, wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_CAUSE);
		writel(0x00, wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK);
		writel(MACREG_A2HRIC_BIT_MASK_MSI, wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_STATUS_MASK);

		/** SC3 MFG FW no longer use this signature
		if (wlpptr->mfgEnable)
		{
			FwReadySignature = FW_LOAD_STA_FWRDY_SIGNATURE;
			OpMode = HostCmd_STA_MODE;
			printk("client mode\n");
		}
		else */
		{
			FwReadySignature = FW_LOAD_SOFTAP_FWRDY_SIGNATURE;
			OpMode = HostCmd_SOFTAP_MODE;
		}
#ifdef SOC_W906X
	}
#endif				/* #ifdef SOC_W906X */

	/* this routine interacts with SC2 bootrom to download firmware binary
	   to the device. After DMA'd to SC2, the firmware could be deflated to reside
	   on its respective blocks such as ITCM, DTCM, SQRAM,
	   (or even DDR, AFTER DDR is init'd before fw download */
	sizeFwDownloaded = 0;
	printk("fw download start 88\n");

#ifdef SOC_W906X
	tick1 = xxGetTimeStamp();

	/* len should not be zero. The first len is 0x10 */
	/* make sure SCRATCH2 C40 is clear, in case we are too quick */
	while (readl(wlpptr->ioBase1 + reg_len_offset) == 0) ;

	while (sizeFwDownloaded < fw_img_len) {
		len = readl(wlpptr->ioBase1 + reg_len_offset);
		if (len > FW_MAX_CHUNK_LEN) {
			printk("bad len: 0x%x !!", len);
			return FAIL;
		}
#else
	/* Disable PFU before FWDL */
	writel(0x100, wlpptr->ioBase1 + 0xE0E4);

	/* make sure SCRATCH2 C40 is clear, in case we are too quick */
	while (readl(wlpptr->ioBase1 + 0xc40) == 0) ;
#ifdef NEW_DP
	/* download ddr init code */
	printk("init ddr...\n");

	while (sizeDdrInitDownloaded < sizeDdrInit) {
		len = readl(wlpptr->ioBase1 + 0xc40);
		if (!len)
			break;

		/* this copies the next chunk of fw binary to be delivered */
		memcpy((char *)&wlpptr->pCmdBuf[0], p, len);

		currIteration = FW_MAX_NUM_CHECKS * 500;	/* this is arbitrary per your platform; we use 0xffff */
		/* this function writes pdata to c10, then write 2 to c18 */
		wltriggerPciCmd_bootcode(netdev);

		/* NOTE: the following back to back checks on C1C is time sensitive, hence  
		   may need to be tweaked dependent on host processor. Time for SC2 to go from 
		   the write of event 2 to C1C == 2 is ~1300 nSec. Hence the checkings on host
		   has to consider how efficient your code can be to meet this timing, or you
		   can alternatively tweak this routines to fit your platform */
		do {
			intCode = readl(wlpptr->ioBase1 + 0xc1c);
			if (intCode != 0)
				break;
			currIteration--;

		} while (currIteration);

		do {
			intCode = readl(wlpptr->ioBase1 + 0xc1c);
			if ((intCode & MACREG_H2ARIC_BIT_DOOR_BELL) != MACREG_H2ARIC_BIT_DOOR_BELL)
				break;
			currIteration--;
		} while (currIteration);

		if (currIteration == 0) {
			/* This limited loop check allows you to exit gracefully without locking up
			   your entire system just because fw download failed */
			printk("Exhausted currIteration during ddr init code download\n");
			wlFwReset(netdev);
			return FAIL;
		}
		p += len;
		sizeDdrInitDownloaded += len;
	}
#endif
	while (sizeFwDownloaded < fw_img_len) {
		len = readl(wlpptr->ioBase1 + 0xc40);
#ifdef SOC_W8964
		if (len > 512) {
			printk("bad len: 0x%x !!", len);
			while (1) ;
		}
#endif
#endif				/* #ifdef SOC_W906X */

		if (!len)
			break;
		/* this copies the next chunk of fw binary to be delivered */
#ifndef SOC_W906X
		memcpy((char *)&wlpptr->pCmdBuf[0], (pFwImage + sizeFwDownloaded), len);
#else
		memcpy((char *)&wlpptr->pFwDlBuf[0], (pFwImage + sizeFwDownloaded), len);
#endif		 /**/
		    currIteration = FW_MAX_NUM_CHECKS;	/* this is arbitrary per your platform; we use 0xffff */
		/* this function writes pdata to c10, then write 2 to c18 */
#ifdef SOC_W906X
		if (IS_BUS_TYPE_MCI(wlpptr))
			fw_chunk_transfer(netdev);
		else
#endif				/* #ifdef SOC_W906X */
			wltriggerPciCmd_bootcode(netdev);

		/* NOTE: the following back to back checks on C1C is time sensitive, hence
		   may need to be tweaked dependent on host processor. Time for SC2 to go from
		   the write of event 2 to C1C == 2 is ~1300 nSec. Hence the checkings on host
		   has to consider how efficient your code can be to meet this timing, or you
		   can alternatively tweak this routines to fit your platform */
		do {
			intCode = readl(wlpptr->ioBase1 + reg_cause_offset);
			if (intCode != 0)
				break;
			currIteration--;
		} while (currIteration);

		do {
			intCode = readl(wlpptr->ioBase1 + reg_cause_offset);
			if ((intCode & MACREG_H2ARIC_BIT_DOOR_BELL) != MACREG_H2ARIC_BIT_DOOR_BELL)
				break;
			currIteration--;
		} while (currIteration);
		if (currIteration == 0) {
			/* This limited loop check allows you to exit gracefully without locking up
			   your entire system just because fw download failed */
			printk("Exhausted currIteration during fw download\n");
#ifdef SOC_W906X
			if (!IS_BUS_TYPE_MCI(wlpptr))
				wlpd_p->downloadSuccessful = 0;
#else
			downloadSuccessful = 0;
#endif				/* #ifdef SOC_W906X */

			wlFwReset(netdev);
			return FAIL;
		}
		sizeFwDownloaded += len;
#ifdef PDM_PCI
		printk("%10d", sizeFwDownloaded);
#endif
	}
#ifdef SOC_W906X
	tick2 = xxGetTimeStamp();
#endif				/* #ifdef SOC_W906X */
#ifdef PDM_PCI
	printk("\n");
#endif
	printk("FwSize = %d downloaded Size = %d currIteration %d\n", (int)fw_img_len, sizeFwDownloaded, currIteration);
#ifdef SOC_W906X
	tick3 = xxGetTimeStamp();
	if (!IS_BUS_TYPE_MCI(wlpptr)) {
		if (!wlpd_p->downloadSuccessful)
			goto complete;
	}
#else
	if (!downloadSuccessful)
		goto complete;
#endif				/* #ifdef SOC_W906X */
	/* Now firware is downloaded successfully, so this part is to check
	   whether fw can properly execute to an extent that write back signature
	   to indicate its readiness to the host. NOTE: if your downloaded fw crashes,
	   this signature checking will fail. This part is similar as SC1 */

#ifndef SOC_W906X
	writew(0x00, &wlpptr->pCmdBuf[1]);
	wltriggerPciCmd(netdev);
#else
	writew(0x00, &wlpptr->pFwDlBuf[1]);
#endif				/* #ifndef SOC_W906X */
	currIteration = FW_MAX_NUM_CHECKS;

	do {
		currIteration--;
		writel(OpMode, wlpptr->ioBase1 + reg_gen_ptr);
#ifdef SOC_W906X
		if (IS_BUS_TYPE_MCI(wlpptr))
			mdelay(FW_CHECK_MSECS);
		else
#endif
			WL_MSEC_SLEEP(FW_CHECK_MSECS);

		intCode = readl(wlpptr->ioBase1 + reg_int_code);
#ifndef SOC_W906X
		if (!(currIteration % 0xff))
			printk("%x;", intCode);
#endif				/* #ifndef SOC_W906X */
	} while ((currIteration) && (intCode != FwReadySignature));

#ifdef SOC_W906X
	tick4 = xxGetTimeStamp();
#endif				/* #ifdef SOC_W906X */

	if (currIteration == 0) {
		printk("Exhausted currIteration waiting for fw signature; firmware seems failed to operate\n");
#ifdef SOC_W906X
		if (!IS_BUS_TYPE_MCI(wlpptr))
			wlpd_p->downloadSuccessful = 0;
#else
		downloadSuccessful = 0;
#endif				/* #ifdef SOC_W906X */
		wlFwReset(netdev);
		return TIMEOUT;
	}

 complete:
#ifdef SOC_W906X
	printk("wlFwDownload complete\nFwDownload time = %u us\nRadio Cal  time = %u us\n", (u32) (tick2 - tick1), (u32) (tick4 - tick3));
	writel(wlpptr->wlpd_p->pPhysCmdBuf, wlpptr->ioBase1 + reg_gen_ptr);

	wlpd_p->downloadSuccessful = TRUE;
#else
	printk("wlFwDownload complete\n");
#endif				/* #ifdef SOC_W906X */
	writel(0x00, wlpptr->ioBase1 + reg_int_code);
	WLDBG_EXIT(DBG_LEVEL_3);
	return SUCCESS;
}

/** private functions **/
#ifndef SOC_W906X
static void wltriggerPciCmd(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	writel(wlpptr->wlpd_p->pPhysCmdBuf, wlpptr->ioBase1 + MACREG_REG_GEN_PTR);

	writel(0x00, wlpptr->ioBase1 + MACREG_REG_INT_CODE);

	writel(MACREG_H2ARIC_BIT_DOOR_BELL, wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
}
#endif				/* #ifndef SOC_W906X */

static void wltriggerPciCmd_bootcode(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef SOC_W906X
	/* write location of data to c10 */
	writel(wlpptr->wlpd_p->pPhysFwDlBuf, wlpptr->ioBase1 + MACREG_REG_GEN_PTR);
#else
	/* write location of data to c10 */
	writel(wlpptr->wlpd_p->pPhysCmdBuf, wlpptr->ioBase1 + MACREG_REG_GEN_PTR);
#endif
	/* write 2 to c18 */
	writel(MACREG_H2ARIC_BIT_DOOR_BELL, wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
}

extern int LoadExternalFw(struct wlprivate *priv, char *filename);
extern int LoadExternalFw_from_cwd(struct wlprivate *priv, char *filename);

#ifdef OPENWRT
#define EXTERNAL_MFG_FILE_NAME_FOR_SC3 "/lib/firmware/wlan-v7_8864/88W8864-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SC4 "/lib/firmware/wlan-v9_8964/88W8964-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SC4P "/lib/firmware/wlan-v9_8964/88W8966-mfg.bin"
#define EXTERNAL_FILE_NAME_FOR_SC3 "/lib/firmware/wlan-v7_8864/W8864.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SC5 "W9068-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SCBT "W9064-mfg.bin"
#ifdef EEPROM_REGION_PWRTABLE_SUPPORT
#define EXTERNAL_FILE_NAME_FOR_SC4 "/lib/firmware/wlan-v9_8964/W8964-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SC4P "/lib/firmware/wlan-v9_8964/W8966-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5  "/lib/firmware/marvell/W9068-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_A0  "/lib/firmware/marvell/W9068-eeprom-A0.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_STA  "/lib/firmware/marvell/W9068-eeprom-STA.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_AP  "/lib/firmware/marvell/W9068-eeprom-AP.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT "/lib/firmware/marvell/W9064-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_A0 "/lib/firmware/marvell/W9064-eeprom-A0.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_STA "/lib/firmware/marvell/W9064-eeprom-STA.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_AP "/lib/firmware/marvell/W9064-eeprom-AP.bin"
#else
#define EXTERNAL_FILE_NAME_FOR_SC4 "/lib/firmware/wlan-v9_8964/W8964.bin"
#define EXTERNAL_FILE_NAME_FOR_SC4P "/lib/firmware/wlan-v9_8964/W8966.bin"
#endif
#else
#define EXTERNAL_MFG_FILE_NAME_FOR_SC3 "88W8864-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SC4 "88W8964-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SC4P "88W8966-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SC5 "W9068-mfg.bin"
#define EXTERNAL_MFG_FILE_NAME_FOR_SCBT "W9064-mfg.bin"
#define EXTERNAL_FILE_NAME_FOR_SC3 "W8864.bin"
#ifdef EEPROM_REGION_PWRTABLE_SUPPORT
#define EXTERNAL_FILE_NAME_FOR_SC4 "W8964-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SC4P "W8966-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5  "W9068-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_A0  "W9068-eeprom-A0.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_STA  "W9068-eeprom-STA.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_AP  "W9068-eeprom-AP.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT "W9064-eeprom.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_A0 "W9064-eeprom-A0.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_STA "W9064-eeprom-STA.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_AP "W9064-eeprom-AP.bin"
#else
#define EXTERNAL_FILE_NAME_FOR_SC4 "W8964.bin"
#define EXTERNAL_FILE_NAME_FOR_SC4P "W8966.bin"
#endif
#endif
#define EXTERNAL_FILE_NAME_FOR_SC5 "W9068.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_A0 "W9068.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_STA "W9068-STA.bin"
#define EXTERNAL_FILE_NAME_FOR_SC5_AP "W9068-AP.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT "W9064.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_A0 "W9064.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_STA "W9064-STA.bin"
#define EXTERNAL_FILE_NAME_FOR_SCBT_AP "W9064-AP.bin"
#define DIR_MARVELL "/marvell/"
#define DIR_NXP "/nxp/"

#ifdef FS_CAL_FILE_SUPPORT
#define EXTERNAL_FILE_NAME_FOR_CONF_FILE "%sWlanCalData_ext_%s.conf"
extern char *CAL_FILE_PATH;
#endif

void wlReleaseFw(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (wlpptr->fw_entry) {
		release_firmware(wlpptr->fw_entry);
	} else {
		wl_kfree(wlpptr->FwPointer);
		wlpptr->FwPointer = NULL;
	}
}

/*
	Loading rules:
	SC5/SCBT:
		- Load W9064-A0.bin / W9068-A0.bin
		- If successful => Using this firmware
		- Othwerwise:
			- If it's (Zx) => failed to run
			- Try to load W9064.bin / W9068.bin
*/
int wlPrepareFwFile(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	char *fw_file = NULL;
#ifdef OPENWRT
	char fw_file_path[255];
#endif
#ifdef DEFAULT_MFG_MODE

	if (wlpptr->devid == SC3) {
		printk("MFG fw file: %s\n", EXTERNAL_MFG_FILE_NAME_FOR_SC3);
		fw_file = EXTERNAL_MFG_FILE_NAME_FOR_SC3;
	} else if (wlpptr->devid == SC4P) {
		printk("MFG file: %s\n", EXTERNAL_MFG_FILE_NAME_FOR_SC4P);
		fw_file = EXTERNAL_MFG_FILE_NAME_FOR_SC4P;
#ifdef SOC_W906X
	} else if (wlpptr->devid == SC5) {
		fw_file = EXTERNAL_MFG_FILE_NAME_FOR_SC5;

		switch (wlpptr->hwData.chipRevision) {
		case REV_A0:
			break;
		default:
			WLDBG_ERROR(DBG_LEVEL_0, "=> Unknown revision: %xh, using this fw file: %s\n", wlpptr->hwData.chipRevision, fw_file);
		}
		printk("MFG file: %s\n", fw_file);
	} else if (wlpptr->devid == SCBT) {
		fw_file = EXTERNAL_MFG_FILE_NAME_FOR_SCBT;

		switch (wlpptr->hwData.chipRevision) {
		case REV_A0:
			break;
		default:
			WLDBG_ERROR(DBG_LEVEL_0, "=> Unknown revision: %xh, using this fw file: %s\n", wlpptr->hwData.chipRevision, fw_file);
		}
		printk("MFG file: %s\n", fw_file);
	}
#endif				/* #ifdef SOC_W906X */
	else {			//SC4
		printk("MFG file: %s\n", EXTERNAL_MFG_FILE_NAME_FOR_SC4);
		fw_file = EXTERNAL_MFG_FILE_NAME_FOR_SC4;
	}
#ifdef OPENWRT
	snprintf(fw_file_path, sizeof(fw_file_path), "%s%s", DIR_NXP, fw_file);
	printk("Try fw file: %s\n", fw_file_path);
	if (LoadExternalFw(wlpptr, fw_file_path)) {
		wlpptr->mfgEnable = 1;
		wlpptr->mfgLoaded = 1;
		return SUCCESS;
	}
	snprintf(fw_file_path, sizeof(fw_file_path), "%s%s", DIR_MARVELL, fw_file);
	printk("Try fw file: %s\n", fw_file_path);
	if (LoadExternalFw(wlpptr, fw_file_path)) {
		wlpptr->mfgEnable = 1;
		wlpptr->mfgLoaded = 1;
		return SUCCESS;
	}
#endif
	/* if firmware is not available in /lib/firmware, get firmware at cwd */
	printk("Try fw file: %s\n", fw_file);
	if (LoadExternalFw_from_cwd(wlpptr, fw_file)) {
		wlpptr->mfgEnable = 1;
		wlpptr->mfgLoaded = 1;
		return SUCCESS;
	}
	wlpptr->mfgEnable = 1;
	wlpptr->mfgLoaded = 1;
#else
	wlpptr->mfgEnable = 0;
	wlpptr->mfgLoaded = 0;

	if (wlpptr->devid == SC3) {
		printk("fw file: %s\n", EXTERNAL_FILE_NAME_FOR_SC3);
		if (LoadExternalFw(wlpptr, EXTERNAL_FILE_NAME_FOR_SC3)) {
			return SUCCESS;
		}
	} else if (wlpptr->devid == SC4) {
		printk("fw file: %s\n", EXTERNAL_FILE_NAME_FOR_SC4);
		if (LoadExternalFw(wlpptr, EXTERNAL_FILE_NAME_FOR_SC4)) {
			return SUCCESS;
		}
	} else if (wlpptr->devid == SC4P) {
		printk("fw file: %s\n", EXTERNAL_FILE_NAME_FOR_SC4P);
		if (LoadExternalFw(wlpptr, EXTERNAL_FILE_NAME_FOR_SC4P)) {
			return SUCCESS;
		}
#ifdef SOC_W906X
	} else if (wlpptr->devid == SC5) {
		switch (wlpptr->hwData.chipRevision) {
		case REV_A0:
			fw_file = EXTERNAL_FILE_NAME_FOR_SC5_A0;
			if (reset_mode == 1)
				fw_file = EXTERNAL_FILE_NAME_FOR_SC5_STA;
			else if (reset_mode == 2)
				fw_file = EXTERNAL_FILE_NAME_FOR_SC5_AP;
			break;
		default:
			fw_file = EXTERNAL_FILE_NAME_FOR_SC5;
			WLDBG_ERROR(DBG_LEVEL_0, "=> Unknown revision: %xh, use this %s\n", wlpptr->hwData.chipRevision, fw_file);
		};
	} else if (wlpptr->devid == SCBT) {
		switch (wlpptr->hwData.chipRevision) {
		case REV_A0:
			fw_file = EXTERNAL_FILE_NAME_FOR_SCBT_A0;
			if (reset_mode == 1)
				fw_file = EXTERNAL_FILE_NAME_FOR_SCBT_STA;
			else if (reset_mode == 2)
				fw_file = EXTERNAL_FILE_NAME_FOR_SCBT_AP;
			break;
		default:
			fw_file = EXTERNAL_FILE_NAME_FOR_SCBT;
			WLDBG_ERROR(DBG_LEVEL_0, "=> Unknown revision: %xh, use this %s\n", wlpptr->hwData.chipRevision, fw_file);
			break;
		}
	}
#ifdef OPENWRT
	snprintf(fw_file_path, sizeof(fw_file_path), "%s%s", DIR_NXP, fw_file);
	printk("Try fw file: %s\n", fw_file_path);
	if (LoadExternalFw(wlpptr, fw_file_path)) {
		return SUCCESS;
	}

	snprintf(fw_file_path, sizeof(fw_file_path), "%s%s", DIR_MARVELL, fw_file);
	printk("Try fw file: %s\n", fw_file_path);
	if (LoadExternalFw(wlpptr, fw_file_path)) {
		return SUCCESS;
	}
#endif
	/* if firmware is not available in /lib/firmware, get firmware at cwd */
	printk("Try fw file: %s\n", fw_file);
	if (LoadExternalFw_from_cwd(wlpptr, fw_file)) {
		return SUCCESS;
	}
#endif				/* #ifdef SOC_W906X */
#endif				/* #ifdef DEFAULT_MFG_MODE */
	printk("load external .bin file fail\n");
	return FAIL;		/* Load external failed. */
}

#ifdef FS_CAL_FILE_SUPPORT
static int wlHex2Int(char *pHex)
{
	int sum = 0, digit, cnt = 0;
	unsigned char cDigit;

	for (cnt = 0; cnt < 2; cnt++) {
		sum <<= 4;
		cDigit = /*toupper */ (*pHex);
		if (cDigit >= '0' && cDigit <= '9')
			digit = cDigit - '0';
		else
			digit = cDigit - 'A' + 10;
		sum += digit;

		pHex++;
	}

	return sum;
}

static int wlGetCalFile(char *filename, char *kbuf)
{
	struct file *filp;
	int i = 0;
	int skipCount = 6;
	int ret_value = SUCCESS;
	char str_data[2];

	filp = filp_open(filename, 0, 0);

	if (!IS_ERR(filp)) {
		while (i < EEPROM_ON_FILE_MAX_SIZE) {
			if (kernel_read(filp, &str_data[0], 1, &filp->f_pos)) {
				if ((str_data[0] == ' ') || (str_data[0] == '\n') || (str_data[0] == '\r'))
					continue;
				if (kernel_read(filp, &str_data[1], 1, &filp->f_pos)) {

					if (skipCount > 0)
						skipCount--;
					else {
						*(kbuf + i) = (char)wlHex2Int(str_data);
						i++;
					}
				} else
					break;
			} else
				break;
		}

		filp_close(filp, current->files);
	} else {
		WLDBG_WARNING(DBG_LEVEL_3, "%s: open %s Fail\n", __FUNCTION__, filename);
		ret_value = FAIL;
	}

	printk("%s: got %d byte from %s\n", __FUNCTION__, i, filename);

	printk("%s: MFG CHECK -->\n", __FUNCTION__);
	for (skipCount = 0; skipCount < 16; skipCount++)
		printk("0x%02x ", kbuf[skipCount]);
	printk("\n");
	if (i == 0)
		i = EEPROM_ON_FILE_MAX_SIZE;
	for (skipCount = (i - 16); skipCount < i; skipCount++)
		printk("0x%02x ", kbuf[skipCount]);

	printk("\n");
	return ret_value;
}

static int wlGetBufferAddr(struct net_device *netdev, char **dma_buffer, dma_addr_t * dma_handle)
{
	static char *kbuf = NULL;
	static dma_addr_t handle = 0;
	size_t size = EEPROM_ON_FILE_MAX_SIZE;

	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	// First Call will allocated the buffer. After First Call it just return the allocated buffer address unless the NULL parametwr for free buffer
	if ((kbuf == NULL) && (handle == 0))
		kbuf = wl_dma_alloc_coherent(wlpptr->wlpd_p->dev, size, &handle, GFP_KERNEL);

	if ((kbuf == NULL) || (handle == 0)) {
		WLDBG_ERROR(DBG_LEVEL_3, "%s: allocate buffer fail\n", __FUNCTION__);

		return FAIL;
	}

	if (dma_buffer == NULL && dma_handle == NULL) {
		wl_dma_free_coherent(wlpptr->wlpd_p->dev, size, kbuf, handle);

		WLDBG_INFO(DBG_LEVEL_3, "%s: Free MFG host memory 0x%x Size 0x%x Success\n", __FUNCTION__, handle, (int)size);

		kbuf = NULL;
		handle = 0;
	} else {
		*dma_handle = handle;
		*dma_buffer = kbuf;

		WLDBG_INFO(DBG_LEVEL_3, "%s: kbuf=%12p, handle=%12p, size = %d\n", __FUNCTION__, kbuf, (unsigned long *)handle, (int)size);
	}

	return SUCCESS;
}

extern char *SINGLE_MFG_CONF_FILE_NAME;
extern char *DUAL0_MFG_CONF_FILE_NAME;
extern char *DUAL1_MFG_CONF_FILE_NAME;
int wlDownloadMFGFile(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	char *kbuf = NULL;
	dma_addr_t handle = 0;
	char ConfFileName[255];

	UINT32 mfgval = 0;

	if (wlGetBufferAddr(netdev, &kbuf, &handle) == FAIL)
		return FAIL;

	memset(kbuf, 0xFF, EEPROM_ON_FILE_MAX_SIZE);

	sprintf(ConfFileName, EXTERNAL_FILE_NAME_FOR_CONF_FILE, CAL_FILE_PATH, netdev->name);
	//;     printk("Try to read Conf file: %s\n",ConfFileName);
	if (wlGetCalFile(ConfFileName, kbuf) == FAIL) {
		printk("%s: No ext cal data file: %s\n", netdev->name, ConfFileName);
		return FAIL;
	} else {
		printk("%s: Parsing complete for ext cal data file: %s \n", netdev->name, ConfFileName);
	}

	*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_phy_addr) = handle;
	// wlInit() will overwrite the 1KB SMAC config block with the data in smacconfig.
	// Therefore, update the data in smacconfig too for writing back.
	wlpptr->smacconfig.cal_data_conf_phy_addr = handle;
	mfgval = ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_phy_addr;
	if (handle != mfgval) {
		WLDBG_ERROR(DBG_LEVEL_3, "%s: FW memory 0x%x= 0x%x mismach address 0x%x\n", __FUNCTION__,
			    (unsigned int)(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_phy_addr), (int)mfgval, handle);
		WLDBG_INFO(DBG_LEVEL_3, "%s: Prepare MFG host memory 0x%x Success to FW 0x%x, 0x%x\n", __FUNCTION__, handle,
			   (unsigned int)(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_phy_addr), (int)mfgval);
		return FAIL;
	}

	*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_signature) = STA_EE_SIGNATURE;
	// wlInit() will overwrite the 1KB SMAC config block with the data in smacconfig.
	// Therefore, update the data in smacconfig too for writing back.
	wlpptr->smacconfig.cal_data_conf_signature = STA_EE_SIGNATURE;
	mfgval = ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_signature;
	if (STA_EE_SIGNATURE != mfgval) {
		WLDBG_ERROR(DBG_LEVEL_3, "%s: FW memory 0x%x=0x%x mismach address 0x%x\n", __FUNCTION__,
			    (unsigned int)(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_signature), (unsigned int)mfgval,
			    STA_EE_SIGNATURE);
		return FAIL;
	}
	WLDBG_INFO(DBG_LEVEL_3, "%s: Prepare MFG host memory 0x%x Success to FW 0x%x\n", __FUNCTION__, handle,
		   (unsigned int)(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.cal_data_conf_phy_addr));

	return SUCCESS;
}

int wlFreeMFGFileBuffer(struct net_device *netdev)
{
	if (wlGetBufferAddr(netdev, NULL, NULL) == FAIL)
		return FAIL;

	return SUCCESS;
}
#endif
