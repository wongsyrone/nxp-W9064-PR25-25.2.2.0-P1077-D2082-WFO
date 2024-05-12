#
# Copyright (C) 2014-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wlan-v9
PKG_RELEASE=4

PKG_LICENSE:=Proprietary
PKG_LICENSE_FILES:=

PKG_MAINTAINER:=Rujun Wang <loganw@marvell.com>
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

PKG_CONFIG_DEPENDS:= \
	CONFIG_MARVELL_WLAN_SOURCES

define KernelPackage/wlan-v9_8964
  SUBMENU:=Wireless Drivers
  TITLE:=Marvell 88W8964 property wireless driver
  DEPENDS:= \
	+@DRIVER_11N_SUPPORT @PCI_SUPPORT @TARGET_mvebu +@DRIVER_WEXT_SUPPORT \
	+wireless-tools
  FILES:=$(PKG_BUILD_DIR)/ap8x.ko
  AUTOLOAD:=$(call AutoLoad,91,ap8x)
endef

define KernelPackage/wlan-v9_8964/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare

ifdef CONFIG_MARVELL_WLAN_SOURCES
	git clone git@github.com:wrt32x/private.git $(BUILD_DIR)/_private
	cd $(BUILD_DIR)/_private && git checkout 06e8fdfde48b51f86d60e8fd7dc6cab96022cc81
	$(CP) $(BUILD_DIR)/_private/wlan-v9/* $(PKG_BUILD_DIR)
	rm -rf $(BUILD_DIR)/_private
	find $(PKG_BUILD_DIR) -type f -exec chmod +w {} \;
else
		$(CP) ./files/shipped/* $(PKG_BUILD_DIR)
endif
endef

define Build/Compile
		rm -f $(PKG_BUILD_DIR)/.prepared*
ifdef CONFIG_MARVELL_WLAN_SOURCES
		$(MAKE) V=1 $(PKG_JOBS) -C "$(PKG_BUILD_DIR)" \
			KDIR="$(LINUX_DIR)" \
			ARCH="$(LINUX_KARCH)" \
			CROSS_COMPILE="$(TARGET_CROSS)" \
			PWD=$(PKG_BUILD_DIR) \
			SOC=W8964 \
			HOST=OPENWRT \
			BUILD_DFS_PASSIVE_SCAN=1 \
			BUILD_MRVL_PMF=1 \
			BUILD_MRVL_MUG=0 \
			BUILD_DFS_SCANNER_SUPPORT=0 \
            all
endif
endef

define KernelPackage/wlan-v9_8964/install
		$(INSTALL_DIR) $(1)/lib/firmware
		$(INSTALL_DIR) $(1)/lib/firmware/wlan-v9_8964
		$(INSTALL_DIR) $(1)/etc
		$(INSTALL_DIR) $(1)/etc/mrvl
		$(CP) ./files/etc/mrvl/* $(1)/etc/mrvl/
		$(INSTALL_DIR) $(1)/etc/init.d
		$(CP) $(PKG_BUILD_DIR)/*.bin $(1)/lib/firmware/wlan-v9_8964/
		$(CP) ./files/etc/* $(1)/etc
		$(CP) ./files/lib/* $(1)/lib
		$(CP) ./files/etc/init.d/* $(1)/etc/init.d
endef

$(eval $(call KernelPackage,wlan-v9_8964))
