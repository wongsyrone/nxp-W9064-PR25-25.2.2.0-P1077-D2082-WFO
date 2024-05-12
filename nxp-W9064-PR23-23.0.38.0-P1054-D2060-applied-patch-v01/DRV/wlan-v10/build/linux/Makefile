ifeq (y, $(CONFIG_GCOV_KERNEL))
EXTRA_CFLAGS+= --coverage -O0
LIBS += -lgcov
endif

DRIVER-OBJS = ap8x-objs
API-OBJS = ap8x-objs
AP-OBJS = ap8x-objs

#set W906x as default if SOC not defined
SOC:= W906x

ifeq (W8964, $(SOC))
APS=16
endif

#Set equal to 1 to build with client code, else 0
BUILD_CLIENT=1

#Set to 1 for A3900 Axis-BT + PDM platform
PDM_PCI=0

#Cap Tx max rate
BUILD_CAP_MAX_RATE=1

#802.11v support
BUILD_DOT11V_DMS=0

ifeq (1, $(BUILD_CLIENT))
#Set equal to 1 in order compile in WPS client code
BUILD_WPS_CLIENT=1
#Set equal to 1 in order to compile DFS channel support and DFS passive scan for channels 52 to 64 and 100 to 140
BUILD_DFS_PASSIVE_SCAN = 1
#Set equal to 1 to include EWB FEATURE
BUILD_EWB=1
endif

#Set equal to 1 in order compile in multicast proxy code
BUILD_MPRXY=1
#Set equal to 1 to include TSO SUPPORT
#Enable TSO by default for L26; L24 does not support TSO
BUILD_TSO=0
#Set equal to 1 to include Dynamic BA Support
BUILD_DYNAMIC_BA=1
#Set equal to 1 to include WFA 11n TKIP Negative tests
BUILD_WFA_TKIP_NEGATIVE = 1

#set equal to 1 to include rx path interrupt reduction
BUILD_RXPATHOPT=0

#set to 1 to enable tcp ack enhancement
BUILD_TCP_ACK_ENHANCEMENT = 1

#Set equal to 1 to include SC2 Palladium simulation development.
PALLADIUM=0

#Set equal to 1 to include BF MIMO Ctrl Field Logging
BUILD_BF_MIMO_CTRL_FIELD_LOGGING = 0

#Set equal to 1 to include spectrum support.
BUILD_SSU_SUPPORT = 1

#Set equal to 1 to include PRD CSI DMA Support
BUILD_PRD_CSI_DMA = 1

#Set equal to 1 to use region power support in EEPROM
#FW also needs equivalent flag set
BUILD_EEPROM_REGION_PWRTABLE_SUPPORT = 0

#Set equal to 1 to enable No EEPROM Cal Data Conf File Support
BUILD_FS_CAL_FILE_SUPPORT = 1

#Set equal to 1 to support Fine Timing Measurement
#ifeq (1, $(WLS))
BUILD_WLS_FTM=0
#endif
#ifeq (1, $(AOA_ONLY))
BUILD_AOA_PROC=0
#endif

#Set equal to 1 to enable SW MU-MIMO steering vector computation
ifeq (1, $(SW_MIMO))
BUILD_SW_MIMO=1
endif

ifeq (1, $(PALLADIUM))
BUILD_SC_PALLADIUM=1
endif

ifeq (1, $(PDM_PCI))
BUILD_PDM_PCI=1
endif

BUILD_STADB_IN_CACHE=1
BUILD_MRVL_PMF = 1

ifeq (1, $(ENABLE_GCOV))
BUILD_GCOV_SUPPORT=1
endif

#Set equal to 1 to enable packet statistics code.
BUILD_QUEUE_STATS_LATENCY=0
BUILD_QUEUE_STATS_CNT_HIST=1

#Set equal to 1,2, or 3 to enable packet statistics code in compile time.
ifeq (1, $(QUEUE_STATS))
BUILD_QUEUE_STATS_LATENCY=1
endif
ifeq (2, $(QUEUE_STATS))
BUILD_QUEUE_STATS_CNT_HIST=1
endif
ifeq (3, $(QUEUE_STATS))
BUILD_QUEUE_STATS_LATENCY=1
BUILD_QUEUE_STATS_CNT_HIST=1
endif
BUILD_NEW_DP=1
BUILD_NEWDP_ACNT_BA=1

#Set 1 to enable Monitor interface support
BUILD_MONIF=1

#Set 1 to enable WTP support
BUILD_WTP_SUPPORT=1

#set 1 to enable MV_NSS_SUPPORT
BUILD_MV_NSS_SUPPORT=0

#set 1 to reset metadata for Marvell NSS
BUILD_MV_NSS_METADATA_RESET=0

#Set to 1 to pass down full HT_cap 28bytes and VHT_cap 14 bytes (including ID & len) when add new client
BUILD_STA_FULL_HTVHT_CAP = 1

#set 1 to enable FIPS support
BUILD_FIPS_SUPPORT = 1

#Set 1 to build in Throughput Profile APIs
ifeq (W906x, $(SOC))
BUILD_TP_PROFILE = 1
BUILD_RX_REPLAY_DETECTION = 1
else
BUILD_TP_PROFILE = 0
endif

#Set 1 to check buffer corruption
BUILD_BUF_CHK_DBG = 0

#set 1 to enable AP SCAN support
AP_SCAN_SUPPORT=1

#Set equal to 1 to include band steering support.
BUILD_BAND_STEERING = 1

#Set equal to 1 to include cfg80211 support.
#BUILD_CFG80211 = 1

#Set equal to 1 to use cfg80211 compatiable.
#CFG80211_COMPATIABLE = 1

#Set to 1 to support MRVL dynamic MU grouping
ifeq (W906x, $(SOC))
BUILD_MRVL_MUG = 0
else
BUILD_MRVL_MUG = 1
endif

#set 1 to enable DFS scanner support
BUILD_DFS_SCANNER_SUPPORT = 1
ifeq (W906x, $(SOC))
BUILD_CONCURRENT_DFS_SUPPORT = 1

else
BUILD_CONCURRENT_DFS_SUPPORT = 0
endif

#Set to 1 to support airtime fairness scheduler
BUILD_AIRTIME_FAIRNESS = 1

#Set to 1 to support debug features of airtime fairness scheduler
BUILD_AIRTIME_FAIRNESS_TRACES = 0

#Set to 1 to support 802.11k neighbor list
ifeq (W906x, $(SOC))
BUILD_IEEE80211K = 1
else
BUILD_IEEE80211K = 0
endif

#Set to 1 to support WMM-AdmissionControl for EDCA
BUILD_WMM_AC_EDCA = 0

#Set to 1 to support AP steering 802.11v
ifeq (W906x, $(SOC))
BUILD_AP_STEERING_SUPPORT = 1
else
BUILD_AP_STEERING_SUPPORT = 0
endif

#Set to 1 to support multi-ap and 4-addr
BUILD_MULTI_AP_SUPPORT = 1

BUILD_SYSFS_STADB_INFO = 1

BUILD_MEMORY_USAGE_TRACE = 0

#Set to 1 to support WIFI ZIGBEE coex
BUILD_WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER = 1

#Set 1 to enable wldbg debug output. Default is disable.
ifeq (W906x, $(SOC))
WLDBG=0
else
WLDBG = 1
endif

#Set 1 to enable IOCTL cmds logging function (also need active bit0 of deb_level)
IOCTLLOG=1

#Set 1 to enable FW cmds logging function (also need active bit1 of dbg_level)
FWCMDLOG=1

DRV=driver/$(SOC)


#Set 1 to build DSP command
BUILD_DSP_COMMAND = 1

#Set 1 to build DSP intertupt mode for R7-A7 intercom
BUILD_DSP_INT_MODE = 0

#Set 1 to use enable configurable multicast/broadcast rates
BUILD_CONFIG_MC_BC_RATE = 1

#Set equal to 1 to enable dynamic CCK-desense.
BUILD_CCK_DESENSE = 1

$(DRIVER-OBJS)	:= \
		$(DRV)/ap8xLnxDesc.o 	\
		driver/ap8xLnxFwdl.o		\
		driver/ap8xLnxFwcmd.o		\
		driver/ap8xLnxIntf.o		\
		driver/ap8xLnxApi.o		\
		$(DRV)/ap8xLnxRecv.o		\
		$(DRV)/ap8xLnxXmit.o		\
		driver/ap8xLnxStat.o		\
		driver/ap8xLnxWlLog.o	\
		driver/ap8xLnxDump.o \
		$(DRV)/ap8xLnxUtil.o


ifeq (1, $(BUILD_CFG80211))
ifeq (W906x, $(SOC))
$(DRIVER-OBJS)	+= \
		$(DRV)/cfg80211.o \
		$(DRV)/vendor.o \
		$(DRV)/event.o
else
$(DRIVER-OBJS)	+= \
		$(DRV)/cfg80211.o \
		$(DRV)/vendor.o \
		$(DRV)/event.o \
		$(DRV)/drv_config.o
endif
endif

ifeq (W906x, $(SOC))
$(DRIVER-OBJS)	+= \
		$(DRV)/ap8xLnxBQM.o	\
		$(DRV)/ap8xLnxEvent.o		\
		$(DRV)/ap8xLnxMonitor.o
endif

$(DRIVER-OBJS)	+= \
		$(DRV)/ioctl_cfg80211.o

# ATKK
$(DRIVER-OBJS)	+= \
		$(DRV)/ap8xLnxCB.o
		
# RxInfo Process
$(DRIVER-OBJS)	+= \
		$(DRV)/ap8xLnxRxInfo.o


# Tx/Rx Accounting Record (dbg sniffer)
$(DRIVER-OBJS)	+= \
		driver/ap8xLnxAR.o

ap8x-$(CONFIG_TRACEPOINTS) += $(DRV)/trace.o

$(API-OBJS)	+= \
		core/api/wlFun.o		\
		core/api/wlApi.o

$(AP-OBJS)		+= \
		core/dbg/wldebug.o 		\
		core/encr/aes_key_wrap.o \
		core/encr/hmac_md5.o \
		core/encr/prfapi.o \
		core/encr/pbkdf2.o \
		core/encr/md5.o \
		core/encr/sha1.o \
		core/encr/tkip.o \
		core/encr/AP/ccmpAP.o \
		core/encr/AP/keyMgmt.o \
		core/encr/AP/tkipAP.o \
		core/wlsys/bcngen.o \
		core/wlsys/hal_mib.o \
		core/wlsys/hal_sys.o \
		core/wlsys/w81init.o \
		core/mgt/mhsm.o \
		core/mgt/List.o \
		core/mgt/timer.o \
		core/mgt/AP/AssocSrvAp.o \
		core/mgt/AP/AuthSrvAp.o \
		core/mgt/AP/idList.o \
		core/mgt/AP/macmgmtap.o \
		core/mgt/AP/macMgmtEvt.o \
		core/mgt/AP/macMgmtMlme.o \
		core/mgt/AP/mlmeApi.o \
		core/mgt/AP/mlmeAuth.o \
		core/mgt/AP/smeMain.o \
		core/mgt/AP/StaDb.o \
		core/mgt/AP/SyncSrvAp.o \
		core/mgt/AP/util.o \
		core/mgt/AP/wlMlmeSrv.o \
		core/mib/mib.o \
		core/mib/wl_mib.o \
		core/os/os_if.o \
		core/qos/qos.o \
		core/qos/qos_back.o \
		core/qos/AP/qos_dlp.o \
		core/qos/AP/qos_scheduler.o \
		core/wlsys/domain.o \
		core/wlsys/packet.o \
		core/wlsys/fragment.o \
		core/wlsys/autochannel.o \
        core/mgt/AP/dfsSM.o \
        core/mgt/AP/dfsEv.o \
        core/wds/wds.o

ifeq (1, $(BUILD_MRVL_PMF))
	$(AP-OBJS)	+= \
		core/encr/AP/aes-omac1.o \
		core/encr/AP/aes-gmac.o \
		core/encr/AP/aes-cmac.o \
		core/encr/AP/aes-internal.o \
		core/encr/AP/aes-internal-enc.o 
endif

ifeq (1, $(BUILD_CLIENT))
	$(AP-OBJS)	+= \
		core/mgt/STA/AssocSta_sm.o \
		core/mgt/STA/AssocSta_srv.o \
		core/mgt/STA/AuthSta_sm.o \
		core/mgt/STA/AuthSta_srv.o \
		core/mgt/STA/SyncSta_sm.o \
		core/mgt/STA/SyncSta_srv.o \
		core/mgt/STA/macMgmtEvtSta.o \
		core/mgt/STA/smeStateMgrSta.o \
		core/mgt/STA/mlmeApiSta.o \
		core/mgt/STA/wlvmac.o \
		core/mgt/STA/child_srv.o \
		core/mgt/STA/parent_srv.o \
		core/mgt/STA/wlMlmeSrvSta.o \
		core/wlsys/linkmgt.o \
		core/wlsys/ewb_hash.o \
		core/wlsys/ewb_packet.o \
		core/encr/STA/keyMgmtSta.o
endif

ifeq (W906x, $(SOC))
ifeq (1, $(BUILD_TP_PROFILE))
	$(AP-OBJS)	+= \
		core/dbg/wlprofile.o
endif
ifeq (1, $(BUILD_WLS_FTM))
	$(DRIVER-OBJS)	+= \
		core/wls/ap8xLnxWls.o core/wls/ap8xLnxCsi.o
	EXTRA_CFLAGS += -DWLS_FTM_SUPPORT -DWLS_LCI_SUPPORT -DIEEE80211K -DUSE_AOA_CAL_DATA -DUSE_FW_SEND_CMD -DPRD_CSI_DMA -I${PWD}/core/wls
#	EXTRA_CFLAGS += -DWLS_FTM_SUPPORT -DWLS_LCI_SUPPORT -DIEEE80211K -DUSE_AOA_CAL_DATA -DUSE_FW_SEND_CMD -DPRD_CSI_DMA  -DPLUGFEST_ONGOING -I${PWD}/core/wls
endif
ifeq (1, $(BUILD_AOA_PROC))
	$(DRIVER-OBJS)	+= \
		core/wls/ap8xLnxCsi.o
	EXTRA_CFLAGS += -DAOA_PROC_SUPPORT -DUSE_AOA_CAL_DATA -DPRD_CSI_DMA -I${PWD}/core/wls
endif
endif

ifeq (1, $(BUILD_SW_MIMO))
	$(DRIVER-OBJS)	+= \
		core/sw_mimo/ap8xLnxSwMimo.o
	EXTRA_CFLAGS += -DPRD_CSI_DMA0 -I${PWD}/core/sw_mimo
endif


#obj-$(CONFIG_MARVELL_SOFTAP) += ap8x.o
obj-m += ap8x.o
	
AS		= $(CROSS_COMPILE)as
ifeq (BE,$(ENDIAN))
LD		= $(CROSS_COMPILE)ld -EB
else
LD		= $(CROSS_COMPILE)ld
endif
CC		= $(CROSS_COMPILE)gcc

SHAL_INC = $(PWD)/../../SHAL/shal1/include
CMIF_INC = $(PWD)/../../CMIF/include

EXTRA_CFLAGS+= -I${KDIR}

ifeq (W906x, $(SOC))
EXTRA_CFLAGS+= -Werror
endif

EXTRA_CFLAGS+= -DUSE_TASKLET
#EXTRA_CFLAGS+= -DNAPI
EXTRA_CFLAGS+= -DDRV_SKIP_DEFINE
EXTRA_CFLAGS+= -O2 -funroll-loops

EXTRA_CFLAGS+=-I${PWD} -I${PWD} -I${PWD}/driver -I${PWD}/$(DRV) -I${PWD}/core/api -I${PWD}/core/incl -I${PWD}/core/mgt/STA/incl -I$(SHAL_INC) -I$(CMIF_INC)

ifeq (BE,$(ENDIAN))
EXTRA_CFLAGS+=-DMV_CPU_BE
else
EXTRA_CFLAGS+=-DMV_CPU_LE
endif

EXTRA_CFLAGS+=-DMV_LINUX -DMV_ARM

EXTRA_CFLAGS+= -DUDP_API -DAP_MAC_LINUX \
		-DIEEE80211H -DWPA -DAP_WPA2 -DQOS_FEATURE -DSTA_INFO_DB \
		-DBT_COEXISTENCE -DAVOID_MIS_ACC -DQOS_WSM_FEATURE
EXTRA_CFLAGS+= -DRELEASE_11N
EXTRA_CFLAGS+= -DAGG_QUE
EXTRA_CFLAGS+= -DAP8X_STATISTICS
EXTRA_CFLAGS+= -DENABLE_WLSNDEVT
EXTRA_CFLAGS+= -DAP8X_DUMP -DAUTOCHANNEL -DENABLE_WLSYSLOG -DUAPSD_SUPPORT
EXTRA_CFLAGS+= -DAMPDU_SUPPORT 
EXTRA_CFLAGS+= -DMRV_8021X 
EXTRA_CFLAGS+= -DINTEROP -DAMSDU_BYTE_REORDER
EXTRA_CFLAGS+= -DWDS_FEATURE
EXTRA_CFLAGS+= -DBRS_SUPPORT
EXTRA_CFLAGS+= -DIEEE80211_DH
EXTRA_CFLAGS+= -DZERO_COPY_RX
EXTRA_CFLAGS+= -DMFG_SUPPORT
EXTRA_CFLAGS+= -DPWRFRAC
EXTRA_CFLAGS+= -DMRVL_WSC
#EXTRA_CFLAGS+= -DMRVL_WAPI
EXTRA_CFLAGS+= -DMRVL_DFS
EXTRA_CFLAGS+= -DEXCLUDE_DFS_CHANNEL
#EXTRA_CFLAGS+= -DWMON
#EXTRA_CFLAGS+= -DINTOLERANT40
EXTRA_CFLAGS+= -DIEEE80211N_MIMOPSD110
EXTRA_CFLAGS+= -DCOEXIST_20_40_SUPPORT
EXTRA_CFLAGS+= -DGENERIC_GETIE
#EXTRA_CFLAGS+= -DWNM
EXTRA_CFLAGS+= -DSUPPORTED_EXT_NSS_BW
EXTRA_CFLAGS += -DOFFCHANNEL_SUPPORT

EXTRA_CFLAGS+= -DOWE_SUPPORT

EXTRA_CFLAGS+= -DMBO_SUPPORT

EXTRA_CFLAGS+= -DCB_SUPPORT

ifeq (1, $(BUILD_WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER))
EXTRA_CFLAGS+= -DWIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER
endif

ifeq (W906x, $(SOC))
EXTRA_CFLAGS+= -DMRVL_80211R
endif

ifeq (1, $(WLDBG))
EXTRA_CFLAGS+= -DWL_DEBUG
endif

ifeq (1, $(IOCTLLOG))
EXTRA_CFLAGS+= -DIOCTL_LOG
endif

ifeq (1, $(FWCMDLOG))
EXTRA_CFLAGS+= -DFWCMD_LOG
endif

EXTRA_CFLAGS+= -DWNC_LED_CTRL

ifeq (W8964, $(SOC))
ifeq (16, $(APS))
EXTRA_CFLAGS+= -DMCAST_PS_OFFLOAD_SUPPORT
endif
else
EXTRA_CFLAGS+= -DMCAST_PS_OFFLOAD_SUPPORT
endif

ifeq (1, $(BUILD_RXPATHOPT))
EXTRA_CFLAGS+= -DRXPATHOPT
endif

ifeq (1, $(BUILD_MRVL_PMF))
EXTRA_CFLAGS+= -DCONFIG_IEEE80211W
endif

ifeq (1, $(BUILD_RX_REPLAY_DETECTION))
EXTRA_CFLAGS+= -DRX_REPLAY_DETECTION
endif

EXTRA_CFLAGS+= -DMRVL_WPS2
EXTRA_CFLAGS+= -DEXPLICIT_BF
ifeq (1,$(BUILD_TCP_ACK_ENHANCEMENT))
    EXTRA_CFLAGS += -DTCP_ACK_ENHANCEMENT
endif

ifeq (1, $(BUILD_EWB))
EXTRA_CFLAGS+= -DEWB
endif

ifeq (1, $(BUILD_TSO))
EXTRA_CFLAGS+= -DWLAN_INCLUDE_TSO
endif

EXTRA_CFLAGS+= -DMBSS -DCOMMON_PHYDSSS -DMIMO_PS_HT -DNPROTECTION

ifeq (1, $(BUILD_CLIENT))
EXTRA_CFLAGS+= -DCLIENT_SUPPORT -DWPA_STA -DWPA2 -DRSN_RESOLVE -DAMPDU_SUPPORT_TX_CLIENT
endif

ifeq (OPENWRT,$(HOST))
EXTRA_CFLAGS+= -DOPENWRT
endif

ifeq (W8964, $(SOC))
EXTRA_CFLAGS+= -DSOC_W8764 -DSOC_W8864 -DSOC_W8964
endif

ifeq (W906x, $(SOC))
EXTRA_CFLAGS+= -DSOC_W906X
endif

ifeq (1, $(NOFWDL))
EXTRA_CFLAGS+= -DNO_FW_DOWNLOAD
endif

ifeq (1, $(MFGFW))
EXTRA_CFLAGS+= -DDEFAULT_MFG_MODE
endif

ifneq (1, $(WLMEM))
EXTRA_CFLAGS+= -DWLMEM_DISABLED
endif

ifeq (1, $(BUILD_MPRXY))
EXTRA_CFLAGS+= -DMPRXY -DMPRXY_SNOOP -DMPRXY_IGMP_QUERY
endif

ifeq (1, $(BULID_CLIENT_ONLY))
EXTRA_CFLAGS+= -DCLIENTONLY -DSINGLE_DEV_INTERFACE
endif

ifeq (W8964, $(SOC))
ifeq (, $(APS))
EXTRA_CFLAGS+= -DNUMOFAPS=1
else
EXTRA_CFLAGS+= -DNUMOFAPS=$(APS)
endif
endif

ifeq (1, $(V4FW))
EXTRA_CFLAGS+= -DAMPDU_SUPPORT_SBA
EXTRA_CFLAGS+= -DV4FW
endif

ifeq (1, $(BUILD_WPS_CLIENT))
EXTRA_CFLAGS+= -DMRVL_WPS_CLIENT
endif
ifeq (1, $(BUILD_DFS_PASSIVE_SCAN))
EXTRA_CFLAGS+= -DDFS_PASSIVE_SCAN -DDFS_CHNL_SUPPORT
#EXTRA_CFLAGS+= -DDFS_PASSIVE_SCAN -DDFS_CHNL_SUPPORT -DFCC_15E_INTERIM_PLAN
endif
EXTRA_CFLAGS+= -DBA_WATCHDOG
EXTRA_CFLAGS+= -DV6FW -DATTN_RSSI -DAMPDU_SUPPORT_SBA
ifeq (1, $(BUILD_DYNAMIC_BA))
EXTRA_CFLAGS+= -DDYNAMIC_BA_SUPPORT
endif
EXTRA_CFLAGS+= -DAMSDUOVERAMPDU
ifeq (1, $(BUILD_WFA_TKIP_NEGATIVE))
EXTRA_CFLAGS+= -DWFA_TKIP_NEGATIVE
endif
ifeq (1, $(BUILD_SC_PALLADIUM))
EXTRA_CFLAGS+= -DSC_PALLADIUM
endif
ifeq (1, $(BUILD_PDM_PCI))
EXTRA_CFLAGS+= -DPDM_PCI
endif
ifeq (1, $(BUILD_SSU_SUPPORT))
EXTRA_CFLAGS+= -DSSU_SUPPORT
endif
ifeq (1, $(BUILD_PRD_CSI_DMA))
EXTRA_CFLAGS+= -DPRD_CSI_DMA
endif
ifeq (1, $(BUILD_EEPROM_REGION_PWRTABLE_SUPPORT))
EXTRA_CFLAGS+= -DEEPROM_REGION_PWRTABLE_SUPPORT
endif
ifeq (1, $(BUILD_FS_CAL_FILE_SUPPORT))
EXTRA_CFLAGS+= -DFS_CAL_FILE_SUPPORT
endif
ifeq (1, $(BUILD_BF_MIMO_CTRL_FIELD_LOGGING))
EXTRA_CFLAGS+= -DBF_MIMO_CTRL_FIELD_LOGGING
endif
ifeq (1, $(BUILD_QUEUE_STATS_LATENCY))
EXTRA_CFLAGS+= -DQUEUE_STATS_LATENCY -DQUEUE_STATS
endif
ifeq (1, $(BUILD_QUEUE_STATS_CNT_HIST))
EXTRA_CFLAGS+= -DQUEUE_STATS_CNT_HIST
ifeq (0, $(BUILD_QUEUE_STATS_LATENCY))
EXTRA_CFLAGS+= -DQUEUE_STATS
endif
endif
ifeq (1, $(BUILD_CAP_MAX_RATE))
EXTRA_CFLAGS+= -DCAP_MAX_RATE
endif

ifeq (1, $(BUILD_DOT11V_DMS))
EXTRA_CFLAGS+= -DDOT11V_DMS
endif

ifeq (1, $(BUILD_NEW_DP))
EXTRA_CFLAGS+= -DNEW_DP
ifeq (1, $(BUILD_NEWDP_ACNT_BA))
EXTRA_CFLAGS+= -DNEWDP_ACNT_BA
endif
#EXTRA_CFLAGS+= -DNEWDP_ACNT_CHUNKS
EXTRA_CFLAGS+= -DBARBADOS_DFS_TEST
EXTRA_CFLAGS+= -DSADDLE_80MHz
	$(DRIVER-OBJS)	+= driver/ap8xLnxAcnt.o
endif

ifeq (1, $(BUILD_TP_PROFILE))
EXTRA_CFLAGS+=-DTP_PROFILE
endif

ifeq (1, $(BUILD_MONIF))
EXTRA_CFLAGS+=-DENABLE_MONIF
endif

ifeq (1, $(BUILD_WTP_SUPPORT))
EXTRA_CFLAGS+=-DWTP_SUPPORT
endif

ifeq (1, $(BUILD_MV_NSS_SUPPORT))
EXTRA_CFLAGS+=-DMV_NSS_SUPPORT
  ifeq (1, $(BUILD_MV_NSS_METADATA_RESET))
  EXTRA_CFLAGS+=-DMV_NSS_METADATA_RESET
  endif
endif

ifeq (1, $(BUILD_FIPS_SUPPORT))
EXTRA_CFLAGS+=-DFIPS_SUPPORT
endif

ifeq (1, $(BUILD_STA_FULL_HTVHT_CAP))
EXTRA_CFLAGS+=-DSTA_FULL_HTVHT_CAP
endif

ifeq (1, $(BUILD_STADB_IN_CACHE))
EXTRA_CFLAGS+=-DSTADB_IN_CACHE
endif

ifeq (1, $(AP_SCAN_SUPPORT))
EXTRA_CFLAGS+= -DAP_SCAN_SUPPORT
endif

ifeq (1, $(BUILD_BAND_STEERING))
EXTRA_CFLAGS+= -DBAND_STEERING
endif

ifeq (1, $(BUILD_CFG80211))
EXTRA_CFLAGS+= -DCFG80211
ifeq (1, $(CFG80211_COMPATIABLE))
EXTRA_CFLAGS+= -DCFG80211_COMPATIABLE
endif
endif

ifeq (1, $(BUILD_CCK_DESENSE))
EXTRA_CFLAGS+= -DCCK_DESENSE
endif

ifeq (1, $(G3_PLATFORM))
EXTRA_CFLAGS+= -DG3_PLATFORM
endif

# Set to SCBT/SC5 driver 
#EXTRA_CFLAGS+= -DSCBT_QM

# Accounting Record
EXTRA_CFLAGS+= -DACNT_REC
#EXTRA_CFLAGS+= -DTXACNT_REC
#EXTRA_CFLAGS+= -DRXACNT_REC

# Enable/Disable handler for getting unexpected BAR from non-add-ba STA/AssocSta_sm
#EXTRA_CFLAGS+= -DMISC_ACTION

ifeq (1, $(BUILD_BUF_CHK_DBG))
EXTRA_CFLAGS+=-DASSERT_MALBUF
endif

ifeq (1, $(BUILD_DSP_COMMAND))
EXTRA_CFLAGS+=-DDSP_COMMAND
ifeq (1, $(BUILD_DSP_INT_MODE))
EXTRA_CFLAGS+=-DDSP_INT_MODE
endif
ifeq (1, $(BUILD_SW_MIMO))
EXTRA_CFLAGS+=-DDSP_TRIG_CMD
endif
endif

ifeq (1,$(BUILD_MRVL_MUG))
EXTRA_CFLAGS    += -DMRVL_MUG_ENABLE
$(DRIVER-OBJS)  += $(DRV)/ap8xLnxMug.o
endif

ifeq (1, $(BUILD_DFS_SCANNER_SUPPORT))
EXTRA_CFLAGS+= -DRADAR_SCANNER_SUPPORT
ifeq (1, $(BUILD_CONCURRENT_DFS_SUPPORT))
EXTRA_CFLAGS+= -DCONCURRENT_DFS_SUPPORT
endif
endif

ifeq (1,$(BUILD_AIRTIME_FAIRNESS))
EXTRA_CFLAGS += -DAIRTIME_FAIRNESS
$(DRIVER-OBJS)  += driver/ap8xLnxAtf.o
endif

ifeq (1,$(BUILD_AIRTIME_FAIRNESS_TRACES))
EXTRA_CFLAGS += -DAIRTIME_FAIRNESS_TRACES
endif

ifeq (1,$(BUILD_IEEE80211K))
EXTRA_CFLAGS    += -DIEEE80211K
$(DRIVER-OBJS)  += core/mgt/AP/msan_report.o
endif

ifeq (1,$(BUILD_WMM_AC_EDCA))
EXTRA_CFLAGS    += -DWMM_AC_EDCA
endif

ifeq (1,$(BUILD_AP_STEERING_SUPPORT))
EXTRA_CFLAGS    += -DAP_STEERING_SUPPORT
$(DRIVER-OBJS)  += core/mgt/AP/bsstm.o
endif

ifeq (1,$(BUILD_MULTI_AP_SUPPORT))
EXTRA_CFLAGS    += -DMULTI_AP_SUPPORT
$(DRIVER-OBJS)  += core/mgt/AP/1905.o
endif

ifeq (1,$(BUILD_SYSFS_STADB_INFO))
EXTRA_CFLAGS    += -DSYSFS_STADB_INFO
endif

EXTRA_CFLAGS    += -DAP_TWT

ifeq (1,$(BUILD_CONFIG_MC_BC_RATE))
EXTRA_CFLAGS    += -DCONFIG_MC_BC_RATE
endif

ifeq (1,$(BUILD_MEMORY_USAGE_TRACE))
EXTRA_CFLAGS    += -DMEMORY_USAGE_TRACE
endif

ifeq (1,$(BUILD_GCOV_SUPPORT))
# obtain the following compiler options from $(CFLAGS_GCOV) in Linux kernel main Makefile
EXTRA_CFLAGS    += -fprofile-arcs -ftest-coverage -fno-tree-loop-im
endif

#include $(TOPDIR)/Rules.make

all:
	@echo $(if $(findstring MRVL_WPS2,$(EXTRA_CFLAGS)),MRVL_WPS2 defined,Info: MRVL_WPS2 not defined)
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	cp ap8x.ko ap8x-ap.ko


clean:
	rm -f *.o *.a *.s *.ko *.ko.cmd *.o.cmd *.mod.* .ap8x.* $(ap8x-objs)
	find . -name .*.o.cmd -exec rm -f {} \;
	find . -name "*.gcno" -type f -delete
	find . -name "*.gcda" -type f -delete
