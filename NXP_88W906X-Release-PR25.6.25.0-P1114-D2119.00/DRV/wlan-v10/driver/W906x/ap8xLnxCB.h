/** @file ap8xLnxCB.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2020 NXP
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
#ifndef AP8X_CB_H_
#define AP8X_CB_H_

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ieee80211.h>

//#include <linux/ctype.h>

// ================================
// From: 2.2.3
/* Implemented by NXP
 * get_handover_params_cmd: send HANDOVER_START command to target
 * sta_mac: station's MAC address
 */
void get_handover_params_cmd(struct net_device *netdev, char *sta_mac);

/* Callback called by NXP implemented by AT
 * get_handover_params_event: callback when received handover_msg
 * sta_mac: station's MAC address
 * msg: buffer including all handover parameters
 * msg_len: msg buffer length
 * tx_q_size: number of frames in all station's TX queues (all TIDS)
 */
//void get_handover_params_event(char *sta_mac, void *msg, int msg_len, int tx_q_size);

/* Implemented by NXP
 * set_handover_params_cmd: send handover_msg to target
 * sta_mac: station's MAC address
 * msg: buffer including all handover parameters
 * msg_len: msg buffer length
 */
void set_handover_params_cmd(struct net_device *netdev, char *sta_mac, void *msg, int msg_len);

/* Callback called by NXP implemented by AT
 * set_handover_params_event: callback when received HANDOVER_DONE
 * sta_mac: station's MAC address
 * status: 0 if handover was successful, non-zero otherwise
 */
//void set_handover_params_event(char *sta_mac, int status);

// ================================
// From: 2.3.3
/* Implemented by NXP
 * set_noack: enable or disable noack feature for given sta
 * sta_mac: station's MAC address
 * enable: 1 if auto-gen frames should not be sent, 0 otherwise
 */
void set_noack(struct net_device *netdev, char *sta_mac, int enable);

// ================================
// From: 2.4.3
/* Implemented by NXP or AT
 * send_mcast_pkt: send mcast frame with given iv and SN
 * skb: multicast ethernet frame
 * iv: iv to use in WLAN frame if encrypted mode, ignore otherwise
 * sn: sequence number to use in WLAN frame
 */
void send_mcast_pkt(struct net_device *netdev, struct sk_buff *skb, uint64_t iv, uint16_t sn);

// ================================
// From: 2.6.3
/* Implemented by NXP or AT
 * get_tsf: returns the current 64 bit value of TSF
 */
//uint64_t get_tsf(void);
uint64_t get_tsf(struct net_device *netdev);

/* Implemented by NXP or AT
 * set_tsf: set new value of tsf and adjust all timers
 */
void set_tsf(struct net_device *netdev, uint64_t tsf);

/*
* adjust_tsf: adjust new value of tsf according to given delta and adjust all timers
* netdev: the net_device pointer of the network interface
* delta: value to add to current value of tsf (can be negative)
*/
void adjust_tsf(struct net_device *netdev, int64_t delta);

// ================================
// From: 2.8.3
/* Implemented by NXP
 * get_rssi: returns the current rssi average over all types of frames
 * sta_mac: station's MAC address
 */
//uint16_t get_rssi(char *sta_mac);
//uint16_t get_rssi(struct net_device* netdev, char *sta_mac);
uint16_t get_rssi(struct net_device *netdev, char *sta_mac, UINT16 * ctrl_rssi, bool reset_ctrl_rssi);

// ================================
struct net_device *get_netdev(char *dev_name);
extern void set_cb(struct net_device *netdev, u8 mode, int is_resp_mgmt);

extern void set_cust_ie(struct net_device *netdev, UINT8 * buf, UINT8 len);

/*
* set_cbcallbk_func: Pass the pointers of the callback functions
*/
/* Callback called by NXP implemented by AT
 * get_handover_params_event: callback when received handover_msg
 * sta_mac: station's MAC address
 * msg: buffer including all handover parameters
 * msg_len: msg buffer length
 * tx_q_size: number of frames in all station's TX queues (all TIDS)
 */

/* Callback called by NXP implemented by AT
 * set_handover_params_event: callback when received HANDOVER_DONE
 * sta_mac: station's MAC address
 * status: 0 if handover was successful, non-zero otherwise
 */

/* Callback called by NXP before each beacon (CB implemented by AT)
 * beacon_update: called before each beacon and if returns non-zero the beacon will be dropped
 * bssid: bssid of beacon
 * skb: beacon frame that can be changed
 */
/*
 * chk_mcpkt_rdy: Is the multicast packets dl path available
 * 	netdev: the net_device pointer of the network interface
 */
bool chk_mcpkt_rdy(struct net_device *netdev);

typedef struct _cbcallbk_intf {
	void (*get_handover_params_event) (char *sta_mac, void *msg, int msg_len, int tx_q_size);
	void (*set_handover_params_event) (char *sta_mac, int status);
	int (*beacon_update) (char *bssid, struct sk_buff * skb, uint64_t ts);
} cbcallbk_intf;
void set_cbcallbk_func(struct net_device *netdev, cbcallbk_intf * pcallcb_func);

void bcn_timer_routine(unsigned long arg);
void cb_mcpkt_timer_routine(unsigned long arg);
bool cb_tx_allow(struct net_device *netdev, struct sk_buff *skb, void *pStaInfo, int type);
void cb_set_bcn_mask(struct net_device *netdev, bool is_on);
void cb_set_bcn_sn(struct net_device *netdev, U16 sn);
U16 cb_get_bcn_sn(struct net_device *netdev);

#endif				//AP8X_CB_H_
