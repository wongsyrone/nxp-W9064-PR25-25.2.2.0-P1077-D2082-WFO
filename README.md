## Some Notes

1. To get firmware blob version:

   Search for this pattern `xx xx 03 00 xx xx 03 00 xx xx 05 00 xx xx 03 00 xx xx 04 00 xx xx 07 00` and the following DWORD is the version in little endian format.

2. `-DEEPROM_REGION_PWRTABLE_SUPPORT` is Read Power Table from eeprom, someone should use firmware blob with '-eeprom.bin' suffix.

3. `-DCONFIG_IEEE80211W` is WPA3 PMF related

4. `-DEXPLICIT_BF` seems to be MU-MIMO related

5. The general definition for 88W8964 is `-DSOC_W8764 -DSOC_W8864 -DSOC_W8964` and New Data Path(NDP), they are `-DNEW_DP -DNEWDP_ACNT_BA`, `ACNT` might refer to accounting.

6. I really don't know what is `MUG` in marvell's terminology, it might refer to `MU grouping`, the definition is `-DMRVL_MUG_ENABLE`, the file is `ap8xLnxMug.c`

7. I found it has Airtime fairness(ATF), this might be used for Mesh networking, def: `-DAIRTIME_FAIRNESS`, file: `ap8xLnxAtf.c`

8. Important files

   | FileName       | Usage                                                        | Remark                                      |
   | -------------- | ------------------------------------------------------------ | ------------------------------------------- |
   | ap8xLnxIntf.c  | Initialization of the interface                              | PCIe, module refer count, interface up/down |
   | ap8xLnxFwcmd.c | Commands sending to the core  wireless firmware              |                                             |
   | ap8xLnxFwdl.c  | How they download the core wireless firmware via PCI bootrom | signatures to signal ready state            |
   | ap8xLnxDesc.c  | PCI descriptors, especially for NDP                          | rx/tx ring alloc/free/reset                 |
   | ap8xLnxXmit.c  | From Ethernet to WLAN                                        |                                             |
   | ap8xLnxRecv.c  | From WLAN to Ethernet                                        |                                             |

   

