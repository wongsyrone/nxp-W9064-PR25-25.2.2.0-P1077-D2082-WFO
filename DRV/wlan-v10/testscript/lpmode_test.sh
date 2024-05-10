insmod ap8x-v10.ko
sleep 1
iwpriv wdev0 setcmd "bpei"
sleep 1
iwpriv wdev0 setcmd "debug addsta 005043200304 2 0"
sleep 1
iwpriv wdev0 setcmd "debug addbss"
sleep 1
# Set loopback mode
#devmem2 0xf8000010 w 0x1
iwpriv wdev0 setcmd "setreg addr0 0x10 1"
sleep 1
#devmem2 0xf8000800
iwpriv wdev0 setcmd "setreg addr0 0x800"
sleep 1

# Get firmware version
iwpriv wdev0 setcmd "setreg addr0 0x410"
sleep 1
iwpriv wdev0 setcmd "setreg addr0 0x414"
sleep 1
iwpriv wdev0 setcmd "setreg addr0 0x418"

# Enable rx-desc / rx-pkt_payload message
iwpriv wdev0 setcmd "pktmsg 0xc"

# Run the loopback test
i=1
max=10
if [ $# -gt 0 ]; then
	max=$1
fi

echo max = $max, i = $i
while [ 1 ]
do

if [ $i -gt $max ]; then
	break;
fi

	echo run $i th times 
	sleep 1
	iwpriv wdev0 setcmd "idx_test 1"
	sleep 1
#	devmem2 0xf8000420
	iwpriv wdev0 setcmd "setreg addr0 0x420"	
	#iwpriv wdev0 setcmd "setreg addr0 0x400"
	#iwpriv wdev0 setcmd "setreg addr0 0x800"
	sleep 1
#	devmem2 0xf800043c
	iwpriv wdev0 setcmd "setreg addr0 0x43c"
	sleep 1
	iwpriv wdev0 setcmd "loopback 1 1 8"
	sleep 1

i=$((i+1))
done

