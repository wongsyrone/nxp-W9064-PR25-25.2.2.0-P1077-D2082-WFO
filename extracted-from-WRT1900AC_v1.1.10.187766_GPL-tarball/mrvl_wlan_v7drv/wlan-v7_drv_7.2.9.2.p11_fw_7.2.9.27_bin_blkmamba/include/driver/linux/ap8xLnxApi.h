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
#ifndef	AP8X_API_H_
#define	AP8X_API_H_

int wldo_ioctl(struct net_device *dev , struct ifreq  *rq, int cmd);
struct iw_statistics *wlGetStats(struct net_device *dev);

extern int wlIoctl(struct net_device *dev , struct ifreq  *rq, int cmd);
extern int wlSetupWEHdlr(struct net_device *netdev);

#endif /* AP8X_API_H_ */





