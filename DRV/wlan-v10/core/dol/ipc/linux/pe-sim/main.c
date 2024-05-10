/** @file main.c
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

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include "ipc.h"
#include "radio.h"
#include "pe.h"

#define PE_SIM_DESC "NXP Wifi Data Off Load Packet Engine Simulator"

static struct task_struct *pe_sim_task;

static int
pe_sim_thread(void *data)
{
	struct radio *radio;
	int i;
	ca_uint32_t cur_local_us;
	ca_uint32_t cur_jiffies;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		ipc_check_msg();
		for (i = 0; i < SYSADPT_MAX_RADIO; i++) {
			radio = &radio_info[i];
			if ((radio->initialized) && (radio->enable) &&
			    !(radio->suspend)) {
				if (!radio->stop_wifi_polling) {
					rx_poll(radio->rid);
					tx_poll(radio->rid);
					rx_refill(radio->rid);
					tx_done(radio->rid);
				}
#ifdef BA_REORDER
				ba_check_timer(radio->rid);
#endif
				cur_local_us = LOCAL_US_TIMER;
				if (DIFF_UINT32
				    (radio->pre_poll_us,
				     cur_local_us) <
				    SYSADPT_MIN_DELTA_TIME_PER_POLL) {
					radio->stop_wifi_polling = true;
				} else {
					radio->stop_wifi_polling = false;
					radio->pre_poll_us = cur_local_us;
				}
				cur_jiffies = jiffies;
				if (DIFF_UINT32
				    (JIFFIES_TO_MSECS
				     (radio->pre_active_notify_jiffies),
				     JIFFIES_TO_MSECS(cur_jiffies)) >
				    SYSADPT_ACTIVE_NOTIFY_PERIOD) {
					radio->pre_active_notify_jiffies =
						cur_jiffies;
					stadb_active_notify(radio->rid);
				}
			}
		}
		schedule_timeout(HZ / HZ);
	}

	return 0;
}

static int
pe_sim_init_module(void)
{
	int err;

	eth_init();

	ipc_init();

	pe_init();

	pe_sim_task = kthread_create(pe_sim_thread, NULL, "pe_sim_task");

	if (IS_ERR(pe_sim_task)) {
		printk(KERN_ERR "Unable to start kernel thread.\n");
		err = PTR_ERR(pe_sim_task);
		pe_sim_task = NULL;
		return err;
	}

	wake_up_process(pe_sim_task);

	printk("%s\n", PE_SIM_DESC);
	printk("version: %s\n", WFO_VERSION);

	return 0;
}

static void
pe_sim_clean_module(void)
{
	if (pe_sim_task) {
		kthread_stop(pe_sim_task);
		pe_sim_task = NULL;
	}

	pe_deinit();

	ipc_deinit();

	eth_deinit();
}

module_init(pe_sim_init_module);
module_exit(pe_sim_clean_module);

MODULE_DESCRIPTION(PE_SIM_DESC);
MODULE_VERSION(WFO_VERSION);
MODULE_AUTHOR("NXP Semiconductor, Inc.");
MODULE_LICENSE("GPL");
