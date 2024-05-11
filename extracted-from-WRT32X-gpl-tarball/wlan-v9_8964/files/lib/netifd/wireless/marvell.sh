#!/bin/sh
. /lib/netifd/netifd-wireless.sh

init_wireless_driver "$@"

MP_CONFIG_INT="mesh_retry_timeout mesh_confirm_timeout mesh_holding_timeout mesh_max_peer_links
	       mesh_max_retries mesh_ttl mesh_element_ttl mesh_hwmp_max_preq_retries
	       mesh_path_refresh_time mesh_min_discovery_timeout mesh_hwmp_active_path_timeout
	       mesh_hwmp_preq_min_interval mesh_hwmp_net_diameter_traversal_time mesh_hwmp_rootmode
	       mesh_hwmp_rann_interval mesh_gate_announcements mesh_sync_offset_max_neighor
	       mesh_rssi_threshold mesh_hwmp_active_path_to_root_timeout mesh_hwmp_root_interval
	       mesh_hwmp_confirmation_interval mesh_awake_window mesh_plink_timeout"
MP_CONFIG_BOOL="mesh_auto_open_plinks mesh_fwding"
MP_CONFIG_STRING="mesh_power_mode"

drv_marvell_init_device_config() {
	logger "init_device_config: $1 $2"
	logger $(json_dump)
	config_add_boolean optlevel rifs preamble gprotect htprotect dhenable dmode hdfsmode hcsamode intolerant40 beamforming
	config_add_int regioncode agingtime ratectl rateb rateg raten ratea rateac ratemu ratema htpc hcsacount hnoptout hcactout opmode
}

drv_marvell_init_iface_config() {
	logger "init_iface_config: $1 $2"
	logger $(json_dump)
	config_add_string bandsteerintf
	config_add_boolean intrabss wdsenable wpsenable bandsteer macclone
	config_add_int bkcwminap bkcwmaxap bkaifsnap bktxopblap bktxopglap bkcwminsta bkcwmaxsta bkaifsnsta bktxopblsta bktxopglsta \
		bkacm becwminap becwmaxap beaifsnap betxopblap betxopglap becwminsta becwmaxsta beaifsnsta betxopblsta betxopglsta beacm \
		vicwminap vicwmaxap viaifsnap vitxopblap vitxopglap vicwminsta vicwmaxsta viaifsnsta vitxopblsta vitxopglsta viacm \
		vocwminap vocwmaxap voaifsnap votxopblap votxopglap vocwminsta vocwmaxsta voaifsnsta votxopblsta votxopglsta voacm \
		disableassoc wdsport wdsmacaddr wdsmode amsdu ampdutx fltmode maclist1 maclist2 maclist3 maclist4 maclist5 index pmfmode
}

marvell_hostapd_setup_bss() {
	local ifname="$1"
	local type="$2"

	hostapd_cfg=
	append hostapd_cfg "bridge=br-lan" "$N"
	append hostapd_cfg "driver=marvell" "$N"
	append hostapd_cfg "$type=$ifname" "$N"
	append hostapd_cfg "ctrl_interface=/var/run/hostapd" "$N"
	append hostapd_cfg "ctrl_interface_group=0" "$N"
	append hostapd_cfg "ap_isolate=0" "$N"
	append hostapd_cfg "ignore_broadcast_ssid=0" "$N"
	append hostapd_cfg "uapsd_advertisement_enabled=1" "$N"

	cat >> /var/run/hostapd-$ifname.conf <<EOF
$hostapd_cfg
EOF
}

marvell_setup_dev() {
	logger "marvell_setup_dev: $1"
	json_select config
	json_get_vars channel txantenna rxantenna rts hwmode htmode beacon_int greenfield tx_stbc short_gi_20 optlevel rifs preamble \
		regioncode agingtime gprotect ratectl rateb rateg raten ratea rateac ratemu ratema dhenable dmode hdfsmode htpc hcsamode \
		hcsacount hnoptout hcactout intolerant40 beamforming opmode
	json_select ..

	case "$htmode" in
		*20*)
		    iwpriv wdev${1#radio} htbw 2
		;;
		*40*)
		    iwpriv wdev${1#radio} htbw 3
		;;
		*80*)
		    iwpriv wdev${1#radio} htbw 4
		;;
		*160*)
		    iwpriv wdev${1#radio} htbw 5
		;;
		*)
		    iwpriv wdev${1#radio} htbw 0
		;;
	esac

	case "$channel" in
		"auto")
			iwpriv wdev${1#radio} autochannel 1
		;;
		*)
			iwpriv wdev${1#radio} autochannel 0
			iwconfig wdev${1#radio} channel $channel
		;;
	esac

	if [ $dhenable == "1" ]; then
		if [ -n "$dmode" ]; then
			iwpriv wdev${1#radio} 11dmode $dmode
		fi

		if [ -n "$hdfsmode" ]; then
			iwpriv wdev${1#radio} 11hspecmgt $hdfsmode
		fi

		if [ -n "$htpc" ]; then
			iwpriv wdev${1#radio} 11hpwrconstr $htpc
		fi

		if [ -n "$hcsamode" ]; then
			iwpriv wdev${1#radio} 11hcsamode $hcsamode
		fi

		if [ -n "$hcsacount" ]; then
			iwpriv wdev${1#radio} 11hcsacount $hcsacount
		fi

		if [ -n "$hnoptout" ]; then
			iwpriv wdev${1#radio} 11hNOPTimeOut $hnoptout
		fi

		if [ -n "$hcactout" ]; then
			iwpriv wdev${1#radio} 11hCACTimeOut $hcactout
		fi
	fi

	case "$txantenna" in
		0)
			iwpriv wdev${1#radio} txantenna 0
		;;
		1)
			iwpriv wdev${1#radio} txantenna 1
		;;
		2)
			iwpriv wdev${1#radio} txantenna 3
		;;
		3)
			iwpriv wdev${1#radio} txantenna 7
		;;
	esac

	case "$rxantenna" in
		0)
			iwpriv wdev${1#radio} rxantenna 0
		;;
		1)
			iwpriv wdev${1#radio} rxantenna 1
		;;
		2)
			iwpriv wdev${1#radio} rxantenna 2
		;;
		3)
			iwpriv wdev${1#radio} rxantenna 3
		;;
	esac

	if [ -n "$rts" ]; then
		iwconfig wdev${1#radio} rts $rts
	fi

	if [ -n "$optlevel" ]; then
		iwpriv wdev${1#radio} optlevel $optlevel
	fi

	if [ -n "$greenfield" ]; then
		iwpriv wdev${1#radio} htgf $greenfield
	fi

	if [ -n "$tx_stbc" ]; then
		iwpriv wdev${1#radio} htstbc $tx_stbc
	fi

	if [ -n "$short_gi_20" ]; then
		iwpriv wdev${1#radio} guardint $short_gi_20
	fi

	if [ -n "$rifs" ]; then
		iwpriv wdev${1#radio} setcmd "rifs $rifs"
	fi

	if [ -n "$preamble" ]; then
		iwpriv wdev${1#radio} preamble $preamble
	fi

	if [ -n "$agingtime" ]; then
		iwpriv wdev${1#radio} agingtime $agingtime
	fi

	if [ -n "$regioncode" ]; then
		iwpriv wdev${1#radio} regioncode $regioncode
	fi

	if [ -n "$gprotect" ]; then
		iwpriv wdev${1#radio} gprotect $gprotect
	fi

	if [ -n "$htprotect" ]; then
		iwpriv wdev${1#radio} htprotect $htprotect
	fi

	if [ -n "$ratectl" ]; then
		iwpriv wdev${1#radio} fixrate $ratectl
	fi

	if [ -n "$rateb" ]; then
		iwpriv wdev${1#radio} txrate "b $rateb"
	fi

	if [ -n "$rateg" ]; then
		iwpriv wdev${1#radio} txrate "g $rateg"
	fi

	if [ -n "$ratea" ]; then
		iwpriv wdev${1#radio} txrate "a $ratea"
	fi

	if [ -n "$raten" ]; then
		iwpriv wdev${1#radio} txrate "n $raten"
	fi

	if [ -n "$rateac" ]; then
		iwpriv wdev${1#radio} txrate "vht $rateac"
	fi

	if [ -n "$ratemu" ]; then
		iwpriv wdev${1#radio} txrate "mcbc $ratemu"
	fi

	if [ -n "$ratema" ]; then
		iwpriv wdev${1#radio} txrate "mgt $ratema"
	fi

	if [ -n "$intolerant40" ]; then
		iwpriv wdev${1#radio} setcmd "intolerant40 $intolerant40"
	fi

	if [ -n "$beamforming" ]; then
		if [ "$beamforming" == "1" ]; then
			iwpriv wdev${1#radio} setcmd "set_bftype 6"
		else
			iwpriv wdev${1#radio} setcmd "set_bftype 5"
		fi
	fi
}

marvell_setup_vif() {
	logger "marvell_setup_vif: $1"
	local name="$1"
	json_select config
	json_get_vars phy ifname mode macaddr ssid encryption key key1 key2 key3 key4 hidden dtim_period auth_server auth_port \
		auth_secret acct_server acct_port acct_secret nasid intrabss htprotect wmm macclone bkcwminap bkcwmaxap bkaifsnap \
		bktxopblap bktxopglap bkcwminsta bkcwmaxsta bkaifsnsta bktxopblsta bktxopglsta bkacm becwminap becwmaxap beaifsnap \
		betxopblap betxopglap becwminsta becwmaxsta beaifsnsta betxopblsta betxopglsta beacm vicwminap vicwmaxap viaifsnap \
		vitxopblap vitxopglap vicwminsta vicwmaxsta viaifsnsta vitxopblsta vitxopglsta viacm vocwminap vocwmaxap voaifsnap \
		votxopblap votxopglap vocwminsta vocwmaxsta voaifsnsta votxopblsta votxopglsta voacm wdsenable disableassoc wdsport \
		wdsmacaddr wdsmode amsdu ampdutx wpsenable bssid fltmode maclist1 maclist2 maclist3 maclist4 maclist5 index \
		bandsteer bandsteerintf pmfmode
	json_select ..

	case "$mode" in
		"ap")
			[ -n "$ifname" ] || ifname="wdev${phy#radio}ap${index}"

			hostapd_conf_file="/var/run/hostapd-$ifname.conf"

			# Hostapd will handle recreating the interface
			type=interface

			marvell_hostapd_setup_bss "$ifname" "$type" || return

			[ -n "$hostapd_ctrl" ] || {
				hostapd_ctrl="${hostapd_ctrl:-/var/run/hostapd/$ifname}"
			}
		;;
		"sta")
			[ -n "$ifname" ] || ifname="wdev${phy#radio}sta0"
		;;
	esac

	wdsmacaddr=`echo $wdsmacaddr | sed 's/://g'`
	bssid=`echo $bssid | sed 's/://g'`
	ip link set dev "$ifname" down

	hostapd_cfg=
	append hostapd_cfg "ssid=$ssid" "$N"
	if [ -n "$beacon_int" ]; then
		append hostapd_cfg "beacon_int=$beacon_int" "$N"
	fi
	if [ -n "$dtim_period" ]; then
		append hostapd_cfg "dtim_period=$dtim_period" "$N"
	fi

	maclist1=`echo $maclist1 | sed 's/://g'`
	maclist2=`echo $maclist2 | sed 's/://g'`
	maclist3=`echo $maclist3 | sed 's/://g'`
	maclist4=`echo $maclist4 | sed 's/://g'`
	maclist5=`echo $maclist5 | sed 's/://g'`

	if [ -n "$wmm" ]; then
		iwpriv wdev${phy#radio} wmm $wmm
	fi

	case "$hwmode" in
		"11a")
			append hostapd_cfg "hw_mode=a" "$N"
			if [ -n "$opmode" ]; then
				case $opmode in
					28)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211ac=1" "$N"
					;;
					24)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211ac=1" "$N"
					;;
					13)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					12)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					8)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
					;;
					*)
						logger "opmode:${opmode} not supported!"
					;;
				esac
			else
				case $htmode in
					HT*)
						iwpriv wdev${phy#radio} opmode 12
						iwpriv $ifname opmode 12
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					VHT*)
						iwpriv wdev${phy#radio} opmode 28
						iwpriv $ifname opmode 28
						append hostapd_cfg "ieee80211ac=1" "$N"
					;;
					*)
						iwpriv wdev${phy#radio} opmode 8
						iwpriv $ifname opmode 8
					;;
				esac
			fi
			append hostapd_cfg "track_sta_max_num=100" "$N"
			append hostapd_cfg "track_sta_max_age=180" "$N"
		;;
		"11g")
			append hostapd_cfg "hw_mode=g" "$N"
			if [ -n "$opmode" ]; then
				case $opmode in
					23)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
					;;
					7)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					6)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					4)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					3)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
					;;
					2)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
					;;
					1)
						iwpriv wdev${phy#radio} opmode $opmode
						iwpriv $ifname opmode $opmode
					;;
					*)
						logger "opmode:${opmode} not supported!"
					;;
				esac
			else
				case $htmode in
					HT*)
						iwpriv wdev${phy#radio} opmode 7
						iwpriv $ifname opmode 7
						append hostapd_cfg "ieee80211n=1" "$N"
					;;
					VHT*)
						iwpriv wdev${phy#radio} opmode 23
						iwpriv $ifname opmode 23
					;;
					*)
						iwpriv wdev${phy#radio} opmode 3
						iwpriv $ifname opmode 3
					;;
				esac
			fi
			if [ "$bandsteer" == "1" ]; then
				append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
				append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
			fi
		;;
		*)
			logger "hwmode:${hwmode} not supported!"
		;;
	esac

	iwconfig wdev${phy#radio} commit

	if [ -n "$amsdu" ]; then
		iwpriv "$ifname" amsdu $amsdu
	fi

	if [ -n "$ampdutx" ]; then
		iwpriv "$ifname" ampdutx $ampdutx
	fi

	if [ -n "$intrabss" ]; then
		iwpriv "$ifname" intrabss $intrabss
	fi

	if [ "$mode" == "sta" ]; then
		iwconfig $ifname essid $ssid
		if [ "$phy" == "radio0" ]; then
			iwpriv $ifname stamode 8
		elif [ "$phy" == "radio1" ]; then
			iwpriv $ifname stamode 7
		fi

		if [ -n "$macclone" ]; then
			iwpriv $ifname macclone $macclone
		fi

		if [ -n "$bkcwminsta" -a -n "$bkcwmaxsta" -a -n "$bkaifsnsta" -a -n "$bktxopblsta" -a -n "$bktxopglsta" -a -n "$bkacm" ]; then
			iwpriv "$ifname" wmmedcasta "1 $bkcwminsta $bkcwmaxsta $bkaifsnsta $bktxopblsta $bktxopglsta $bkacm"
		fi

		if [ -n "$becwminsta" -a -n "$becwmaxsta" -a -n "$beaifsnsta" -a -n "$betxopblsta" -a -n "$betxopglsta" -a -n "$beacm" ]; then
			iwpriv "$ifname" wmmedcasta "0 $becwminsta $becwmaxsta $beaifsnsta $betxopblsta $betxopglsta $beacm"
		fi

		if [ -n "$vicwminsta" -a -n "$vicwmaxsta" -a -n "$viaifsnsta" -a -n "$vitxopblsta" -a -n "$vitxopglsta" -a -n "$viacm" ]; then
			iwpriv "$ifname" wmmedcasta "2 $vicwminsta $vicwmaxsta $viaifsnsta $vitxopblsta $vitxopglsta $viacm"
		fi

		if [ -n "$vocwminsta" -a -n "$vocwmaxsta" -a -n "$voaifsnsta" -a -n "$votxopblsta" -a -n "$votxopglsta" -a -n "$voacm" ]; then
			iwpriv "$ifname" wmmedcasta "3 $vocwminsta $vocwmaxsta $voaifsnsta $votxopblsta $votxopglsta $voacm"
		fi
    fi
	case "$encryption" in
		"psk+tkip")
			echo "WPA TKIP"
			if [ "$mode" == "sta" ]; then
				iwpriv $ifname wpawpa2mode 1
				iwpriv $ifname passphrase "wpa $key"
				iwpriv $ifname grouprekey 1800
			elif [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=1" "$N"
				append hostapd_cfg "wpa_pairwise=TKIP" "$N"
				append hostapd_cfg "wpa_key_mgmt=WPA-PSK" "$N"
				append hostapd_cfg "wpa_passphrase=$key" "$N"
				append hostapd_cfg "wpa_group_rekey=1800" "$N"
			fi
		;;
		"psk2")
			echo "WPA2 CCMP"
			if [ "$mode" == "sta" ]; then
				iwpriv $ifname wpawpa2mode 2
				iwpriv $ifname passphrase "wpa2 $key"
				iwpriv $ifname grouprekey 1800
			elif [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=2" "$N"
				append hostapd_cfg "wpa_pairwise=CCMP" "$N"
				append hostapd_cfg "wpa_key_mgmt=WPA-PSK" "$N"
				append hostapd_cfg "wpa_passphrase=$key" "$N"
				append hostapd_cfg "wpa_group_rekey=1800" "$N"
			fi
		;;
		"psk-mixed+tkip+ccmp")
			echo "WPA-TKIP/WPA2-CCMP"
			if [ "$mode" == "sta" ]; then
				iwpriv $ifname wpawpa2mode 3
				iwpriv $ifname passphrase "wpa $key"
				iwpriv $ifname passphrase "wpa2 $key"
				iwpriv $ifname grouprekey 1800
			elif [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=3" "$N"
				append hostapd_cfg "wpa_pairwise=TKIP" "$N"
				append hostapd_cfg "rsn_pairwise=CCMP" "$N"
				append hostapd_cfg "wpa_key_mgmt=WPA-PSK" "$N"
				append hostapd_cfg "wpa_passphrase=$key" "$N"
				append hostapd_cfg "wpa_group_rekey=1800" "$N"
			fi
		;;
		"wpa+tkip")
			echo "WPA-EAP TKIP"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=1" "$N"
			append hostapd_cfg "wpa_pairwise=TKIP" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			append hostapd_cfg "acct_server_port=$acct_port" "$N"
			append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			append hostapd_cfg "nas_identifier=$nasid" "$N"
		;;
		"wpa2+ccmp")
			echo "WPA2-EAP CCMP"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=2" "$N"
			append hostapd_cfg "wpa_pairwise=CCMP" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			append hostapd_cfg "acct_server_port=$acct_port" "$N"
			append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			append hostapd_cfg "nas_identifier=$nasid" "$N"
		;;
		"wpa-mixed+tkip+ccmp")
			echo "WPA-EAP TKIP/WPA2-EAP CCMP Mixed"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=3" "$N"
			append hostapd_cfg "wpa_pairwise=TKIP" "$N"
			append hostapd_cfg "rsn_pairwise=CCMP" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			append hostapd_cfg "acct_server_port=$acct_port" "$N"
			append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			append hostapd_cfg "nas_identifier=$nasid" "$N"
		;;
		"wep-shared")
			echo "WEP shared"
			iwpriv $ifname wpawpa2mode 0
			if [ -n "$key1" ]; then
				echo "WEP key1 $key1"
				iwconfig $ifname key $key1 [1]
			fi
			if [ -n "$key2" ]; then
				echo "WEP key2 $key2"
				iwconfig $ifname key $key2 [2]
			fi
			if [ -n "$key3" ]; then
				echo "WEP key3 $key3"
				iwconfig $ifname key $key3 [3]
			fi
			if [ -n "$key4" ]; then
				echo "WEP key4 $key4"
				iwconfig $ifname key $key4 [4]
			fi
			iwconfig $ifname key $key restricted
		;;
		"wep-open")
			echo "WEP open"
			iwpriv $ifname wpawpa2mode 0
			if [ -n "$key1" ]; then
				echo "WEP key1 $key1"
				iwconfig $ifname key $key1 [1]
			fi
			if [ -n "$key2" ]; then
				echo "WEP key2 $key2"
				iwconfig $ifname key $key2 [2]
			fi
			if [ -n "$key3" ]; then
				echo "WEP key3 $key3"
				iwconfig $ifname key $key3 [3]
			fi
			if [ -n "$key4" ]; then
				echo "WEP key4 $key4"
				iwconfig $ifname key $key4 [4]
			fi
			iwconfig $ifname key $key open
		;;
		"none")
			echo "Open"
			iwpriv $ifname wpawpa2mode 0
			iwconfig $ifname key off
		;;
		*)
			echo "Enc:$encryption NOT supported"
		;;
	esac

	if [ "$wpsenable" == "1" ]; then
		append hostapd_cfg "ieee8021x=0" "$N"
		append hostapd_cfg "eapol_key_index_workaround=0" "$N"
		append hostapd_cfg "eap_server=1" "$N"
		append hostapd_cfg "wps_state=2" "$N"
		append hostapd_cfg "ap_setup_locked=0" "$N"
		append hostapd_cfg "device_type=6-0050F204-1" "$N"
		wpsdevice=$(uci get linksys.@hardware[0].modelNumber)
		append hostapd_cfg "device_name=$wpsdevice" "$N"
		append hostapd_cfg "model_name=$wpsdevice" "$N"
		wpsserial=$(uci get linksys.@hardware[0].serial_number)
		append hostapd_cfg "serial_number=$wpsserial" "$N"
		wpsmanuf=$(uci get linksys.@hardware[0].manufacturer)
		append hostapd_cfg "manufacturer=$wpsmanuf" "$N"
		append hostapd_cfg "wps_pin_requests=/var/run/hostapd_wps_pin_requests" "$N"
		append hostapd_cfg "config_methods=label push_button keypad virtual_push_button physical_push_button" "$N"
		wpsuuid=$(uci get linksys.@hardware[0].uuid_key)
		append hostapd_cfg "uuid=$wpsuuid" "$N"
		append hostapd_cfg "upnp_iface=br-lan" "$N"
		wpsappin=$(uci get linksys.@hardware[0].wps_device_pin)
		append hostapd_cfg "ap_pin=$wpsappin" "$N"
		append hostapd_cfg "upnp_iface=br-lan"
		append hostapd_cfg "friendly_name=$wpsdevice" "$N"
	fi

	append hostapd_cfg "okc=0" "$N"
	append hostapd_cfg "disable_pmksa_caching=1" "$N"

	if [ "$mode" == "ap" ]; then
		if [ -n "$fltmode" ]; then
			iwpriv "$ifname" filter $fltmode
			if [ "$fltmode" == "0" ]; then
				iwpriv "$ifname" filtermac "deleteall"
			fi
		fi

		if [ -n "$maclist1" ]; then
			iwpriv "$ifname" filtermac "add $maclist1"
		fi

		if [ -n "$maclist2" ]; then
			iwpriv "$ifname" filtermac "add $maclist2"
		fi

		if [ -n "$maclist3" ]; then
			iwpriv "$ifname" filtermac "add $maclist3"
		fi

		if [ -n "$maclist4" ]; then
			iwpriv "$ifname" filtermac "add $maclist4"
		fi

		if [ -n "$maclist5" ]; then
			iwpriv "$ifname" filtermac "add $maclist5"
		fi

		if [ -n "$dtim_period" ]; then
			iwpriv "$ifname" dtim $dtim_period
		fi

		if [ -n "$bssid" ]; then
			iwpriv "$ifname" bssid $bssid
		fi

		if [ -n "$hidden" ]; then
			iwpriv "$ifname" hidessid $hidden
		fi

		if [ -n "$bkcwminap" -a -n "$bkcwmaxap" -a -n "$bkaifsnap" -a -n "$bktxopblap" -a -n "$bktxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "1 $bkcwminap $bkcwmaxap $bkaifsnap $bktxopblap $bktxopglap"
		fi

		if [ -n "$becwminap" -a -n "$becwmaxap" -a -n "$beaifsnap" -a -n "$betxopblap" -a -n "$betxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "0 $becwminap $becwmaxap $beaifsnap $betxopblap $betxopglap"
		fi

		if [ -n "$vicwminap" -a -n "$vicwmaxap" -a -n "$viaifsnap" -a -n "$vitxopblap" -a -n "$vitxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "2 $vicwminap $vicwmaxap $viaifsnap $vitxopblap $vitxopglap"
		fi

		if [ -n "$vocwminap" -a -n "$vocwmaxap" -a -n "$voaifsnap" -a -n "$votxopblap" -a -n "$votxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "3 $vocwminap $vocwmaxap $voaifsnap $votxopblap $votxopglap"
		fi

		if [ -n "$pmfmode" ]; then
			append hostapd_cfg "ieee80211w=$pmfmode" "$N"
		fi

	fi
	if [ -n "$wdsenable" ]; then
		iwpriv "$ifname" wdsmode $wdsenable
	fi

	if [ -n "$wdsenable" -a -n "$disableassoc" -a -n "$wdsport" -a -n "$wdsmacaddr" -a -n "$wdsmode" ]; then
		iwpriv "$ifname" disableassoc $disableassoc
		iwpriv "$ifname" setwds "$wdsport $wdsmacaddr $wdsmode"
		ifconfig ${ifname}wds${wdsport} up
	fi

	wireless_add_vif $name $ifname

	case "$hwmode" in
		"11a")
			iwpriv wdev0sta0 stamode 8
		;;
		"11g")
			iwpriv wdev1sta0 stamode 7
		;;
		*)
		;;
	esac

	ip link set dev "$ifname" up

	if [ "$mode" == "ap" ]; then
		cat >> /var/run/hostapd-$ifname.conf <<EOF
$hostapd_cfg
EOF
	fi
}

marvell_interface_cleanup() {
	local phy="wdev${1#radio}"

	for wdev in $(list_phy_interfaces "$phy"); do
		ip link set dev "$wdev" down 2>/dev/null
	done
}

marvell_hostapd_cleanup() {
	rm -rf /var/run/hostapd-wdev${1#radio}*.conf
}

drv_marvell_cleanup() {
	logger "drv_marvell_cleanup: $1"
	logger $(json_dump)
}

drv_marvell_setup() {
	lk="/var/lock/marvell.lock"
	lock -w $lk
	lock $lk
	logger "drv_marvell_setup: $1"
	local vif_ifaces vif_iface
	logger $(json_dump)
	json_get_keys vif_ifaces interfaces
	json_select interfaces
	for vif_iface in $vif_ifaces; do
		json_select "$vif_iface"
		json_select config
		json_add_string phy "$1"
		json_select ..
		json_select ..
	done
	json_select ..

	marvell_interface_cleanup "$1"

	marvell_hostapd_cleanup "$1"

	marvell_setup_dev "$1"

	for_each_interface "sta ap" marvell_setup_vif

	#if [ -f /var/run/hostapd.pid ]; then
	#	kill -9 $(cat /var/run/hostapd.pid)
	#	rm -rf /var/run/hostapd/
	#	rm -rf /var/run/hostapd.pid
	#fi
	#if [ "$(find /var/run/ -name hostapd-wdev*.conf)" != "" ]; then
	#	sleep 1
	#	/usr/sbin/hostapd -P /var/run/hostapd.pid -B `ls /var/run/hostapd-wdev*.conf`
	#fi

	if [ "$(find /var/run/ -name hostapd-wdev${1#radio}*.conf)" != "" ]; then
		/usr/sbin/hostapd -P /var/run/wdev${1#radio}.pid -B `ls /var/run/hostapd-wdev${1#radio}*.conf`
		ret="$?"
		wireless_add_process "$(cat /var/run/wdev${1#radio}.pid)" "/usr/sbin/hostapd" 1
		[ "$ret" != 0 ] && {
			wireless_setup_failed HOSTAPD_START_FAILED
			lock -u $lk
			return
		}
	fi

	wireless_set_up
	lock -u $lk
}

list_phy_interfaces() {
	local phy="$1"
	ls "/sys/class/net/" 2>/dev/null|egrep "^${phy}\w+"
}

drv_marvell_teardown() {
	logger "drv_marvell_teardown: $1"
	echo $(json_dump)

	echo "cleanup phy: $1"
	marvell_interface_cleanup "$1"
}

add_driver marvell
