append DRIVERS "marvell"

AAscan_marvell() {
	local device="$1"
	local vif vifs wds
	local adhoc sta apmode mon disabled
	local adhoc_if sta_if ap_if mon_if
}

AAdisable_marvell() {
	local device="$1"
	echo "disable interface $1"
	for wdev in $(ls /sys/class/net/ 2>/dev/null | grep ^$1); do
		ifconfig $wdev down
	done
}

AAenable_marvell() {
	local device="$1"
	local channel country maxassoc wds vifs distance slottime rxantenna txantenna
	local frameburst macfilter maclist macaddr txpower frag rts hwmode htmode
	config_get channel "$device" channel
	config_get country "$device" country
	config_get maxassoc "$device" maxassoc
	config_get wds "$device" wds
	config_get vifs "$device" vifs
	config_get distance "$device" distance
	config_get slottime "$device" slottime
	config_get rxantenna "$device" rxantenna
	config_get txantenna "$device" txantenna
	config_get_bool frameburst "$device" frameburst
	config_get macfilter "$device" macfilter
	config_get maclist "$device" maclist
	config_get txpower "$device" txpower
	config_get frag "$device" frag
	config_get rts "$device" rts
	config_get hwmode "$device" hwmode
	config_get htmode "$device" htmode
	local apcount=0
	local anyup=0
	local netdev=wdev${device#radio}

	echo "channel is $channel, device is $device, netdev is $netdev"
	ifconfig $netdev down
	for vif in $vifs; do
		config_get vifssid "$vif" ssid
		config_get vifwdev "$vif" device
		config_get vifenc "$vif" encryption
		config_get vifdisable "$vif" disabled
		local vifdev=wdev${vifwdev#radio}ap$apcount
		echo "disabled: $vifdisable, ssid: $vifssid, vapdev: $vifdev dev: $vifwdev, enc: $vifenc"
		ifconfig $vifdev down
		if [ "$vifdisable" = "1" ]; then
			echo "skip disabled vif"
			continue
		fi
		if [ -n "$vifssid" ]; then
			iwconfig $vifdev essid $vifssid
		fi
		if [ "$vifdisable" != "none" ]; then
			config_get vifkey "$vif" key
			echo "key: $vifkey"
		fi
		case "$vifenc" in
			"psk2"|"psk2+ccmp"|"psk2+tkip+ccmp")
				echo "WPA2 AES-CCMP"
				iwpriv $vifdev wpawpa2mode 2
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa2 aes-ccmp"
			;;
			"psk2+tkip")
				echo "WPA2 TKIP"
				iwpriv $vifdev wpawpa2mode 2
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa2 tkip"
			;;
			"psk+psk2")
				echo "WPA/WPA2"
				iwpriv $vifdev wpawpa2mode 3
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa tkip"
				iwpriv $vifdev ciphersuite "wpa2 aes-ccmp"
			;;
			"psk"|"psk+tkip"|"psk+tkip+ccmp")
				echo "WPA TKIP"
				iwpriv $vifdev wpawpa2mode 1
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa tkip"
			;;
			"psk"|"psk+ccmp")
				echo "WPA AES-CCMP"
				iwpriv $vifdev wpawpa2mode 1
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa aes-ccmp"
			;;
			"none")
				echo "Open"
				iwpriv $vifdev wpawpa2mode 0
			;;
			*)
				echo "Enc:$vifenc NOT supported"
			;;
		esac
		apcount=$(($apcount+1))
		ifconfig $vifdev up
		anyup=1
	done
	if [ "$anyup" = "1" ]; then
		echo "Up $netdev"
		ifconfig $netdev up
	fi
}


detect_marvell() {
	local i=-1
	while grep -qs "^ *wdev$((++i)):" /proc/net/dev; do
		local channel type
		mode_band="g"
		bandwith="HT20"

		config_get type radio${i} type
		[ "$type" = marvell ] && continue
		#channel=`iwconfig wdev${i} |grep Channel|cut -d ":" -f2|cut -d " " -f1`
		hwaddr=`ifconfig wdev${i}|grep HWaddr|cut -d " " -f10`
		lastbyte=${hwaddr##*:}
		hex="0x"
		lastbyte=${hex}${lastbyte}
		if [ "$i" = "0" ]; then
			mode_band="a"
			bandwith="VHT80"
			essid="OpenWrt"
		fi

		CERT=$(uci get linksys.@hardware[0].cert_region)

		case "$CERT" in
			CN)
				regioncode="0x91"
			;;
			AU)
				regioncode="0x81"
			;;
			AH)
				regioncode="0x90"
			;;
			*)
				regioncode="0x10"
			;;
esac

		cat <<EOF
config wifi-device  radio${i}
	option type     marvell
	option channel  auto
	option hwmode	11${mode_band}
	option htmode	${bandwith}
	option txantenna 0
	option rxantenna 0
	option agingtime 7200
	option beacon_int 100
	option beamforming 1
	option dhenable 1
	option dmode 0
	option gprotect 0
	option greenfield 0
	option hcactout 60
	option hcsacount 20
	option hcsamode 1
	option hdfsmode 1
	option hnoptout 1800
	option htpc 3
	option htprotect 0
	option intolerant40 1
	option optlevel 1
	option preamble 0
	option ratea 108
	option rateac 0x28
	option rateb 22
	option ratectl 0
	option rateg 108
	option ratema 2
	option ratemu 2
	option raten 271
	option regioncode ${regioncode}
	option rifs 0
	option rts 2347
	option short_gi_20 0
	option tx_stbc 0

config wifi-iface
	option device   radio${i}
	option network	lan
	option mode     ap
#	option ssid     Venom
	option bssid	${hwaddr}
	option disabled 0
#	option encryption none
	option hidden 0
	option ampdutx 1
	option amsdu 3
	option bandsteer 0
	option beaifsnap 3
	option becwmaxap 63
	option becwminap 15
	option betxopblap 0
	option betxopglap 0
	option bkaifsnap 7
	option bkcwminap 15
	option bkcwmaxap 1023
	option bktxopblap 0
	option bktxopglap 0
	option disableassoc 1
	option dtim_period 1
	option fltmode 0
	option index 0
	option intrabss 1
	option pmfmode 1
	option viaifsnap 1
	option vicwmaxap 15
	option vicwminap 7
	option vitxopblap 188
	option vitxopglap 94
	option voaifsnap 1
	option vocwmaxap 7
	option vocwminap 3
	option votxopblap 102
	option votxopglap 47
	option wdsenable 0
	option wdsmode g
	option wdsport 0
	option wpsenable 1
	option wmm 1
EOF
	done
}
